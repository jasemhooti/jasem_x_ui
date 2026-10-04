package link

import "testing"

// FuzzParseLink asserts the parser never panics and upholds its (result, error) contract
// — exactly one non-nil. It base64-decodes and type-asserts attacker-controllable JSON,
// the classic panic source.
func FuzzParseLink(f *testing.F) {
	seeds := []string{
		"",
		"not-a-link",
		"vmess://eyJ2IjoiMiIsInBzIjoidCIsImFkZCI6ImEuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi00MzMzLTg0NDQtNTU1NTU1NTU1NTU1IiwibmV0IjoidGNwIn0=",
		"vless://11111111-2222-4333-8444-555555555555@a.com:443?type=tcp&security=none#x",
		"trojan://pass@a.com:443?security=tls#x",
		"ss://YWVzLTI1Ni1nY206cGFzcw==@a.com:8388#x",
		"hysteria2://pass@a.com:443?sni=a.com#x",
		"wireguard://cGsdkey@a.com:51820?publickey=pub#x",
		"socks5://u:p@a.com:1080#x",
		"https://u:p@a.com:443#x",
		"tuic://id:pw@a.com:443?alpn=h3#x",
		"hysteria://a.com:443?auth=t#x",
		"anytls://pw@a.com:443#x",
		"SSH://u:p@a.com#x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		res, err := ParseLink(s)
		if (res == nil) == (err == nil) {
			t.Fatalf("ParseLink(%q): exactly one of (result, error) must be non-nil; got res=%v err=%v", s, res, err)
		}
	})
}
