package link

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

var xrayProxyProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"socks": true, "http": true, "wireguard": true, "hysteria": true,
}

var singboxPassthrough = map[string]bool{
	"tuic": true, "hysteria": true, "anytls": true, "shadowtls": true, "naive": true, "ssh": true,
}

// singboxIgnored are routing/utility outbounds, not servers, so they are not reported as skipped.
var singboxIgnored = map[string]bool{
	"direct": true, "block": true, "dns": true, "selector": true, "urltest": true,
}

func (s *Subscription) addJSON(text string) {
	var doc any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		s.skip(text, fmt.Errorf("invalid json: %v", err))
		return
	}
	s.addJSONValue(doc)
}

func (s *Subscription) addJSONValue(doc any) {
	switch v := doc.(type) {
	case []any:
		for _, e := range v {
			s.addJSONValue(e)
		}
	case map[string]any:
		if list, ok := v["outbounds"].([]any); ok {
			remark := str(v, "remarks", "remark")
			for _, e := range list {
				s.addJSONOutbound(anyMap(e), remark)
			}
			return
		}
		s.addJSONOutbound(v, "")
	}
}

func (s *Subscription) addJSONOutbound(m map[string]any, remark string) {
	if m == nil {
		return
	}
	if typ := strings.ToLower(str(m, "type")); typ != "" && m["protocol"] == nil {
		if singboxIgnored[typ] {
			return
		}
		res, err := singboxJSONOutbound(typ, m)
		if err != nil {
			s.skip(firstNonEmpty(str(m, "tag"), str(m, "server")), err)
			return
		}
		s.add(res)
		return
	}
	protocol := strings.ToLower(str(m, "protocol"))
	if protocol == "" {
		s.skip(firstNonEmpty(str(m, "tag"), "outbound"), fmt.Errorf("unrecognised outbound"))
		return
	}
	if !xrayProxyProtocols[protocol] && protocol != singboxProtocol {
		if protocol != "freedom" && protocol != "blackhole" && protocol != "dns" && protocol != "loopback" {
			s.skip(firstNonEmpty(str(m, "tag"), protocol), fmt.Errorf("unsupported xray protocol %q", protocol))
		}
		return
	}
	ob := Outbound{}
	for k, v := range m {
		ob[k] = v
	}
	if tag := str(m, "tag"); remark != "" && (tag == "" || tag == "proxy") {
		ob["tag"] = remark
	}
	s.add(&ParseResult{Outbound: ob, Identity: "xrayjson:" + objectHash(m)})
}

func objectHash(m map[string]any) string {
	core := map[string]any{}
	for k, v := range m {
		if k != "tag" {
			core[k] = v
		}
	}
	raw, _ := json.Marshal(core)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func singboxJSONOutbound(typ string, m map[string]any) (*ParseResult, error) {
	if singboxPassthrough[typ] {
		ob := map[string]any{}
		for k, v := range m {
			if k != "tag" {
				ob[k] = v
			}
		}
		return &ParseResult{Outbound: singboxPseudo(str(m, "tag"), ob), Identity: "singboxjson:" + objectHash(m)}, nil
	}
	d := &proxyDesc{
		typ: typ, name: str(m, "tag"), server: str(m, "server"),
		port: intOf(m, "server_port"), extra: url.Values{}, security: "none",
	}
	switch typ {
	case "vless":
		d.id, d.flow = str(m, "uuid"), str(m, "flow")
	case "vmess":
		d.id, d.alterID, d.cipher = str(m, "uuid"), str(m, "alter_id"), str(m, "security")
	case "trojan":
		d.password = str(m, "password")
	case "shadowsocks":
		d.typ, d.cipher, d.password = "ss", str(m, "method"), str(m, "password")
		if plugin := str(m, "plugin"); plugin != "" {
			if plugin != "obfs-local" && plugin != "obfs" {
				return nil, fmt.Errorf("shadowsocks plugin %q is not supported", plugin)
			}
			d.plugin = "obfs-local;" + str(m, "plugin_opts")
		}
	case "socks":
		d.id, d.password = str(m, "username"), str(m, "password")
	case "http":
		d.id, d.password = str(m, "username"), str(m, "password")
	case "hysteria2":
		d.password = str(m, "password")
		if obfs := anyMap(m["obfs"]); obfs != nil {
			d.extra.Set("obfs", str(obfs, "type"))
			d.extra.Set("obfs-password", str(obfs, "password"))
		}
		if ports := strList(m["server_ports"]); len(ports) > 0 {
			d.extra.Set("mport", strings.ReplaceAll(strings.Join(ports, ","), ":", "-"))
		}
	default:
		return nil, fmt.Errorf("unsupported sing-box outbound type %q", typ)
	}
	if err := singboxJSONStream(d, m); err != nil {
		return nil, err
	}
	return linkResult(d)
}

func singboxJSONStream(d *proxyDesc, m map[string]any) error {
	d.network = "tcp"
	if tr := anyMap(m["transport"]); tr != nil {
		switch typ := strings.ToLower(str(tr, "type")); typ {
		case "ws", "httpupgrade":
			d.network = typ
			d.path = str(tr, "path")
			d.host = firstNonEmpty(headerHost(tr["headers"]), str(tr, "host"))
		case "grpc":
			d.network, d.serviceName = "grpc", str(tr, "service_name")
		case "xhttp":
			d.network, d.path, d.mode = "xhttp", str(tr, "path"), str(tr, "mode")
			d.host = firstNonEmpty(headerHost(tr["headers"]), str(tr, "host"))
		default:
			return fmt.Errorf("unsupported transport %q", typ)
		}
	}
	tls := anyMap(m["tls"])
	if tls == nil || !boolOf(tls, "enabled") {
		return nil
	}
	d.security = "tls"
	d.sni = str(tls, "server_name")
	d.alpn = strList(tls["alpn"])
	d.insecure = boolOf(tls, "insecure")
	d.fp = str(anyMap(tls["utls"]), "fingerprint")
	if re := anyMap(tls["reality"]); boolOf(re, "enabled") {
		d.security, d.pbk, d.sid = "reality", str(re, "public_key"), str(re, "short_id")
		d.fp = firstNonEmpty(d.fp, "chrome")
	}
	return nil
}
