package link

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const singboxProtocol = "singbox"

// singboxPseudo wraps a sing-box outbound object (without "tag") in the panel's
// pseudo-outbound shape that internal/singbox.Bridge consumes.
func singboxPseudo(tag string, ob map[string]any) Outbound {
	return Outbound{
		"protocol": singboxProtocol,
		"tag":      tag,
		"settings": map[string]any{"outbound": ob},
	}
}

func singboxTLS(p url.Values, host string) map[string]any {
	tls := map[string]any{"enabled": true}
	if sni := firstParam(p, "sni", "peer", "servername"); sni != "" {
		tls["server_name"] = sni
	} else if host != "" {
		tls["server_name"] = host
	}
	switch strings.ToLower(firstParam(p, "insecure", "allow_insecure", "allowInsecure", "skip-cert-verify")) {
	case "1", "true":
		tls["insecure"] = true
	}
	if alpn := p.Get("alpn"); alpn != "" {
		tls["alpn"] = toAnySlice(splitComma(alpn))
	}
	if fp := p.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func parseSingboxLink(link string) (*ParseResult, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%s link has no host", u.Scheme)
	}
	port := defaultPort(u.Port(), 443)
	p := u.Query()
	ob := map[string]any{"server": host, "server_port": port}
	user := u.User.Username()
	pass, _ := u.User.Password()

	switch u.Scheme {
	case "tuic":
		ob["type"] = "tuic"
		ob["uuid"], ob["password"] = user, pass
		if cc := firstParam(p, "congestion_control", "congestion-controller", "congestion"); cc != "" {
			ob["congestion_control"] = cc
		}
		if mode := firstParam(p, "udp_relay_mode", "udp-relay-mode"); mode != "" {
			ob["udp_relay_mode"] = mode
		}
		if isTrue(firstParam(p, "udp_over_stream", "udp-over-stream")) {
			ob["udp_over_stream"] = true
		}
		if isTrue(firstParam(p, "zero_rtt_handshake", "reduce-rtt", "reduce_rtt")) {
			ob["zero_rtt_handshake"] = true
		}
		if hb := firstParam(p, "heartbeat", "heartbeat-interval"); hb != "" {
			ob["heartbeat"] = hb
		}
		tls := singboxTLS(p, host)
		if _, ok := tls["alpn"]; !ok {
			tls["alpn"] = []any{"h3"}
		}
		ob["tls"] = tls
	case "hysteria":
		if proto := strings.ToLower(p.Get("protocol")); proto != "" && proto != "udp" {
			return nil, fmt.Errorf("hysteria v1 protocol %q is not supported", proto)
		}
		ob["type"] = "hysteria"
		ob["up_mbps"] = mbps(firstParam(p, "upmbps", "up"), 50)
		ob["down_mbps"] = mbps(firstParam(p, "downmbps", "down"), 100)
		if auth := firstParam(p, "auth", "auth_str", "auth-str"); auth != "" {
			ob["auth_str"] = auth
		} else if user != "" {
			ob["auth_str"] = user
		}
		if obfs := firstParam(p, "obfsParam", "obfs"); obfs != "" {
			ob["obfs"] = obfs
		}
		tls := singboxTLS(p, host)
		if _, ok := tls["alpn"]; !ok {
			tls["alpn"] = []any{"h3"}
		}
		ob["tls"] = tls
	case "anytls":
		ob["type"] = "anytls"
		ob["password"] = firstNonEmpty(pass, user)
		ob["tls"] = singboxTLS(p, host)
	case "naive+https":
		ob["type"] = "naive"
		ob["username"], ob["password"] = user, pass
		ob["tls"] = singboxTLS(p, host)
	case "ssh":
		ob["type"] = "ssh"
		ob["server_port"] = defaultPort(u.Port(), 22)
		ob["user"] = user
		if pass != "" {
			ob["password"] = pass
		}
		if key := p.Get("private_key"); key != "" {
			ob["private_key"] = key
		}
		if key := p.Get("private_key_path"); key != "" {
			ob["private_key_path"] = key
		}
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
	identity := "singbox:" + u.Scheme + "://" + user + ":" + pass + "@" + host + ":" +
		strconv.Itoa(num(ob["server_port"])) + "?" + canonicalQuery(p)
	return &ParseResult{Outbound: singboxPseudo(decodeHash(u.Fragment), ob), Identity: identity}, nil
}

func isTrue(s string) bool {
	s = strings.ToLower(s)
	return s == "1" || s == "true"
}

// mbps reads the leading number of values like "100" or "100 Mbps".
func mbps(raw string, def int) int {
	digits := strings.TrimSpace(raw)
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	if n, err := strconv.Atoi(digits[:end]); err == nil && n > 0 {
		return n
	}
	return def
}
