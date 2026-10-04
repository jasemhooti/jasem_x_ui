package link

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseProxyLink handles socks[5]:// and http(s):// proxy links. A bare http(s)
// URL without a port is rejected so stray web links in a body are not imported.
func parseProxyLink(link string) (*ParseResult, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("proxy link has no host")
	}
	protocol, secure, def := "socks", false, 1080
	if u.Scheme == "http" || u.Scheme == "https" {
		protocol, secure, def = "http", u.Scheme == "https", 0
		if u.Port() == "" {
			return nil, fmt.Errorf("http proxy link needs an explicit port")
		}
	}
	port := defaultPort(u.Port(), def)
	if port <= 0 {
		return nil, fmt.Errorf("invalid proxy port")
	}
	user, pass := proxyCredentials(u)

	server := map[string]any{"address": host, "port": port, "users": []any{}}
	if user != "" || pass != "" {
		server["users"] = []any{map[string]any{"user": user, "pass": pass}}
	}
	ob := Outbound{
		"protocol": protocol,
		"tag":      decodeHash(u.Fragment),
		"settings": map[string]any{"servers": []any{server}},
	}
	if secure {
		stream := buildStream("tcp", "tls")
		stream["tlsSettings"].(map[string]any)["serverName"] = firstNonEmpty(u.Query().Get("sni"), host)
		ob["streamSettings"] = stream
	}
	identity := protocol + ":" + u.Scheme + "://" + user + ":" + pass + "@" + host + ":" + strconv.Itoa(port)
	return &ParseResult{Outbound: ob, Identity: identity}, nil
}

// proxyCredentials reads user:pass, or the base64(user:pass) userinfo that
// socks:// share links commonly use.
func proxyCredentials(u *url.URL) (string, string) {
	if u.User == nil {
		return "", ""
	}
	user := u.User.Username()
	pass, hasPass := u.User.Password()
	if hasPass {
		return user, pass
	}
	if dec, err := base64DecodeFlexible(user); err == nil {
		if name, secret, ok := strings.Cut(dec, ":"); ok {
			return name, secret
		}
	}
	return user, ""
}
