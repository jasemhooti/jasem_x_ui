package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// proxyDesc is a format-neutral proxy description that Clash and sing-box
// entries are normalised into, then rendered as a share link for ParseLink.
type proxyDesc struct {
	typ, name, server string
	port              int
	id, password      string
	cipher, flow      string
	encryption        string
	alterID           string
	network           string // tcp, ws, grpc, httpupgrade, xhttp
	httpObfs          bool   // tcp with an http header
	host, path        string
	serviceName, mode string
	security          string // none, tls, reality
	sni, fp           string
	alpn              []string
	pbk, sid          string
	insecure          bool
	plugin            string
	extra             url.Values
}

func (d *proxyDesc) link() (string, error) {
	if d.server == "" || d.port <= 0 || d.port > 65535 {
		return "", fmt.Errorf("missing server or port")
	}
	q := url.Values{}
	for k, v := range d.extra {
		q[k] = v
	}
	setIf := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	d.applyStream(q, setIf)
	hostPort := net.JoinHostPort(d.server, strconv.Itoa(d.port))
	build := func(scheme string, user *url.Userinfo) string {
		u := url.URL{Scheme: scheme, User: user, Host: hostPort, RawQuery: q.Encode()}
		return u.String() + "#" + url.QueryEscape(d.name)
	}
	switch d.typ {
	case "vless":
		setIf("flow", d.flow)
		setIf("encryption", d.encryption)
		return build("vless", url.User(d.id)), nil
	case "trojan":
		return build("trojan", url.User(d.password)), nil
	case "vmess":
		return d.vmessLink(), nil
	case "ss":
		if d.plugin != "" {
			q.Set("plugin", d.plugin)
		}
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(d.cipher + ":" + d.password))
		return build("ss", url.User(userinfo)), nil
	case "socks":
		return build("socks5", url.UserPassword(d.id, d.password)), nil
	case "http":
		scheme := "http"
		if d.security == "tls" {
			scheme = "https"
		}
		return build(scheme, url.UserPassword(d.id, d.password)), nil
	case "hysteria2":
		return build("hysteria2", url.User(d.password)), nil
	case "tuic":
		return build("tuic", url.UserPassword(d.id, d.password)), nil
	case "hysteria":
		return build("hysteria", nil), nil
	case "anytls":
		return build("anytls", url.User(d.password)), nil
	}
	return "", fmt.Errorf("unsupported proxy type %q", d.typ)
}

func (d *proxyDesc) applyStream(q url.Values, setIf func(k, v string)) {
	network := firstNonEmpty(d.network, "tcp")
	q.Set("type", network)
	if d.httpObfs {
		q.Set("headerType", "http")
	}
	setIf("host", d.host)
	setIf("path", d.path)
	setIf("serviceName", d.serviceName)
	setIf("mode", d.mode)
	security := firstNonEmpty(d.security, "none")
	switch d.typ {
	case "vless", "trojan":
		q.Set("security", security)
	}
	setIf("sni", d.sni)
	setIf("fp", d.fp)
	setIf("pbk", d.pbk)
	setIf("sid", d.sid)
	if len(d.alpn) > 0 {
		q.Set("alpn", strings.Join(d.alpn, ","))
	}
	if d.insecure {
		q.Set("insecure", "1")
	}
}

func (d *proxyDesc) vmessLink() string {
	j := map[string]any{
		"v": "2", "ps": d.name, "add": d.server, "port": d.port, "id": d.id,
		"aid": firstNonEmpty(d.alterID, "0"), "scy": firstNonEmpty(d.cipher, "auto"),
		"net": firstNonEmpty(d.network, "tcp"), "type": "none",
		"host": d.host, "path": firstNonEmpty(d.path, d.serviceName),
	}
	if d.httpObfs {
		j["type"] = "http"
	}
	if d.network == "xhttp" {
		j["mode"] = d.mode
	}
	if d.security == "tls" {
		j["tls"] = "tls"
		j["sni"], j["fp"] = d.sni, d.fp
		j["alpn"] = strings.Join(d.alpn, ",")
	}
	raw, _ := json.Marshal(j)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// anyMap, str, intOf and strList read loosely typed YAML/JSON values.
func anyMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case bool:
			return strconv.FormatBool(v)
		case nil:
		default:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func intOf(m map[string]any, keys ...string) int {
	n, _ := strconv.Atoi(str(m, keys...))
	return n
}

func boolOf(m map[string]any, keys ...string) bool {
	return isTrue(str(m, keys...))
}

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return splitComma(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s := fmt.Sprint(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// headerHost returns the Host header from a headers map, matching the key
// case-insensitively; the value may be a string or a list.
func headerHost(headers any) string {
	for k, v := range anyMap(headers) {
		if strings.EqualFold(k, "host") {
			return strings.Join(strList(v), ",")
		}
	}
	return ""
}
