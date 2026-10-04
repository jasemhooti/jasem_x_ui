package link

import (
	"fmt"
	"strings"
)

// ParseLink parses a single share link and returns the outbound object plus
// a stable identity for tag correlation. Schemes are case-insensitive:
//   - vmess://, vless://, trojan://, ss:// (modern and legacy)
//   - hysteria2:// (also hy2://), wireguard:// (also wg://)
//   - socks://, socks5://, http://, https:// (proxy links)
//   - tuic://, hysteria://, anytls://, naive+https://, ssh:// (sing-box pseudo-outbound)
func ParseLink(link string) (*ParseResult, error) {
	link = lowerScheme(strings.TrimSpace(link))
	scheme, _, _ := strings.Cut(link, "://")
	switch scheme {
	case "vmess":
		return parseVmess(link)
	case "vless":
		return parseVless(link)
	case "trojan":
		return parseTrojan(link)
	case "ss":
		return parseShadowsocks(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link)
	case "wireguard", "wg":
		return parseWireguard(link)
	case "socks", "socks5", "socks5h", "http", "https":
		return parseProxyLink(link)
	case "tuic", "hysteria", "anytls", "naive+https", "ssh":
		return parseSingboxLink(link)
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
}

func lowerScheme(link string) string {
	if i := strings.Index(link, "://"); i > 0 {
		return strings.ToLower(link[:i]) + link[i:]
	}
	return link
}
