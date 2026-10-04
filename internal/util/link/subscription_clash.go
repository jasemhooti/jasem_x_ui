package link

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

func (s *Subscription) addClash(text string) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		s.skip(text, fmt.Errorf("invalid clash yaml: %v", err))
		return
	}
	for _, m := range doc.Proxies {
		res, err := clashProxy(m)
		if err != nil {
			s.skip(firstNonEmpty(str(m, "name"), str(m, "server")), err)
			continue
		}
		s.add(res)
	}
}

func clashProxy(m map[string]any) (*ParseResult, error) {
	d := &proxyDesc{
		typ: strings.ToLower(str(m, "type")), name: str(m, "name"),
		server: str(m, "server"), port: intOf(m, "port"), extra: url.Values{},
	}
	switch d.typ {
	case "ss", "vmess", "vless", "trojan", "socks5", "http", "hysteria2", "hysteria", "tuic", "anytls":
	default:
		return nil, fmt.Errorf("unsupported clash proxy type %q", d.typ)
	}
	if d.typ == "socks5" {
		d.typ = "socks"
	}
	if err := clashStream(d, m); err != nil {
		return nil, err
	}
	switch d.typ {
	case "vless":
		d.id, d.flow, d.encryption = str(m, "uuid"), str(m, "flow"), str(m, "encryption")
	case "vmess":
		d.id, d.alterID, d.cipher = str(m, "uuid"), str(m, "alterId"), str(m, "cipher")
	case "trojan":
		d.password = str(m, "password")
		d.security = firstNonEmpty(d.security, "tls")
		if d.security == "none" {
			d.security = "tls"
		}
	case "ss":
		d.cipher, d.password = str(m, "cipher"), str(m, "password")
		if err := clashSSPlugin(d, m); err != nil {
			return nil, err
		}
	case "socks", "http":
		d.id, d.password = str(m, "username"), str(m, "password")
	case "hysteria2":
		d.password = str(m, "password")
		d.extra.Set("obfs", str(m, "obfs"))
		d.extra.Set("obfs-password", str(m, "obfs-password"))
		d.extra.Set("mport", str(m, "ports", "mport"))
		d.extra.Set("pinSHA256", str(m, "fingerprint"))
	case "hysteria":
		d.extra.Set("auth", str(m, "auth-str", "auth_str", "auth"))
		d.extra.Set("upmbps", strconv.Itoa(mbps(str(m, "up"), 0)))
		d.extra.Set("downmbps", strconv.Itoa(mbps(str(m, "down"), 0)))
		d.extra.Set("obfsParam", str(m, "obfs"))
		d.extra.Set("protocol", str(m, "protocol"))
	case "tuic":
		d.id, d.password = str(m, "uuid"), str(m, "password")
		d.extra.Set("congestion_control", str(m, "congestion-controller", "congestion_controller"))
		d.extra.Set("udp_relay_mode", str(m, "udp-relay-mode"))
		d.extra.Set("zero_rtt_handshake", str(m, "reduce-rtt"))
		if hb := intOf(m, "heartbeat-interval"); hb > 0 {
			d.extra.Set("heartbeat", strconv.Itoa(hb)+"ms")
		}
	case "anytls":
		d.password = str(m, "password")
	}
	for k, v := range d.extra {
		if len(v) == 0 || v[0] == "" || v[0] == "0" {
			delete(d.extra, k)
		}
	}
	return linkResult(d)
}

func linkResult(d *proxyDesc) (*ParseResult, error) {
	raw, err := d.link()
	if err != nil {
		return nil, err
	}
	return ParseLink(raw)
}

func clashStream(d *proxyDesc, m map[string]any) error {
	network := strings.ToLower(str(m, "network"))
	switch network {
	case "", "tcp":
		d.network = "tcp"
	case "ws":
		d.network = "ws"
		opts := anyMap(m["ws-opts"])
		d.path = firstNonEmpty(str(opts, "path"), str(m, "ws-path"))
		d.host = firstNonEmpty(headerHost(opts["headers"]), headerHost(m["ws-headers"]))
		if boolOf(opts, "v2ray-http-upgrade") {
			d.network = "httpupgrade"
		}
	case "grpc":
		d.network = "grpc"
		d.serviceName = str(anyMap(m["grpc-opts"]), "grpc-service-name")
	case "xhttp":
		d.network = "xhttp"
		opts := anyMap(m["xhttp-opts"])
		d.path, d.mode = str(opts, "path"), str(opts, "mode")
		d.host = firstNonEmpty(str(opts, "host"), headerHost(opts["headers"]))
	case "http":
		d.network, d.httpObfs = "tcp", true
		opts := anyMap(m["http-opts"])
		d.path = strings.Join(strList(opts["path"]), ",")
		d.host = headerHost(opts["headers"])
	default:
		return fmt.Errorf("unsupported transport %q", network)
	}
	switch {
	case anyMap(m["reality-opts"]) != nil:
		ro := anyMap(m["reality-opts"])
		d.security, d.pbk, d.sid = "reality", str(ro, "public-key"), str(ro, "short-id")
		d.fp = firstNonEmpty(str(m, "client-fingerprint"), "chrome")
	case boolOf(m, "tls") || d.typ == "trojan" || d.typ == "hysteria2" || d.typ == "hysteria" || d.typ == "tuic" || d.typ == "anytls":
		d.security = "tls"
		d.fp = str(m, "client-fingerprint", "fingerprint")
		if d.typ == "hysteria2" {
			d.fp = str(m, "client-fingerprint")
		}
	default:
		d.security = "none"
	}
	d.sni = str(m, "servername", "sni", "peer")
	d.alpn = strList(m["alpn"])
	d.insecure = boolOf(m, "skip-cert-verify")
	return nil
}

func clashSSPlugin(d *proxyDesc, m map[string]any) error {
	plugin := str(m, "plugin")
	if plugin == "" {
		return nil
	}
	opts := anyMap(m["plugin-opts"])
	if plugin != "obfs" || str(opts, "mode") != "http" {
		return fmt.Errorf("shadowsocks plugin %q is not supported", plugin)
	}
	d.plugin = "obfs-local;obfs=http"
	if host := str(opts, "host"); host != "" {
		d.plugin += ";obfs-host=" + host
	}
	return nil
}
