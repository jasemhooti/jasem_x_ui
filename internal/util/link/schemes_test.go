package link

import (
	"encoding/json"
	"reflect"
	"testing"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func singboxObj(t *testing.T, res *ParseResult) map[string]any {
	t.Helper()
	if res.Outbound["protocol"] != "singbox" {
		t.Fatalf("protocol = %v, want singbox", res.Outbound["protocol"])
	}
	return res.Outbound["settings"].(map[string]any)["outbound"].(map[string]any)
}

func TestParseLinkSchemeIsCaseInsensitive(t *testing.T) {
	for _, link := range []string{
		"VLESS://uuid@1.2.3.4:443?type=tcp&security=none#a",
		"Vless://uuid@1.2.3.4:443?type=tcp&security=none#a",
		"TROJAN://pw@1.2.3.4:443#a",
		"SS://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#a",
		"Hy2://pw@1.2.3.4:443#a",
		"VMESS://eyJ2IjoiMiIsInBzIjoidCIsImFkZCI6ImEuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMSIsIm5ldCI6InRjcCJ9",
	} {
		res, err := ParseLink(link)
		if err != nil || res == nil {
			t.Errorf("ParseLink(%q) = %v, %v", link, res, err)
		}
	}
}

func TestParseProxyLinks(t *testing.T) {
	tests := []struct {
		name, link, protocol, users string
		tls                         bool
	}{
		{"socks5 plain", "socks5://alice:secret@1.2.3.4:1080#s", "socks", `[{"pass":"secret","user":"alice"}]`, false},
		{"socks base64 userinfo", "SOCKS://YWxpY2U6c2VjcmV0@1.2.3.4:1080#s", "socks", `[{"pass":"secret","user":"alice"}]`, false},
		{"socks anonymous", "socks://1.2.3.4:1080#s", "socks", `[]`, false},
		{"http", "http://bob:pw@1.2.3.4:8080#h", "http", `[{"pass":"pw","user":"bob"}]`, false},
		{"https", "https://bob:pw@proxy.example.com:443#h", "http", `[{"pass":"pw","user":"bob"}]`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseLink(tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if res.Outbound["protocol"] != tc.protocol {
				t.Fatalf("protocol = %v", res.Outbound["protocol"])
			}
			server := res.Outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if got := mustJSON(t, server["users"]); got != tc.users {
				t.Errorf("users = %s, want %s", got, tc.users)
			}
			_, hasStream := res.Outbound["streamSettings"]
			if hasStream != tc.tls {
				t.Errorf("streamSettings present = %v, want %v", hasStream, tc.tls)
			}
		})
	}
	if _, err := ParseLink("https://example.com/page"); err == nil {
		t.Error("bare web URL without port must be rejected")
	}
}

func TestParseSingboxLinks(t *testing.T) {
	tests := []struct {
		name, link, want string
	}{
		{
			"tuic",
			"TUIC://11111111-2222-4333-8444-555555555555:pw@1.2.3.4:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=a.example.com&allow_insecure=1#t",
			`{"congestion_control":"bbr","password":"pw","server":"1.2.3.4","server_port":443,"tls":{"alpn":["h3"],"enabled":true,"insecure":true,"server_name":"a.example.com"},"type":"tuic","udp_relay_mode":"native","uuid":"11111111-2222-4333-8444-555555555555"}`,
		},
		{
			"hysteria v1",
			"hysteria://1.2.3.4:4443?auth=tok&peer=a.example.com&insecure=1&upmbps=20&downmbps=80&obfsParam=xx#h",
			`{"auth_str":"tok","down_mbps":80,"obfs":"xx","server":"1.2.3.4","server_port":4443,"tls":{"alpn":["h3"],"enabled":true,"insecure":true,"server_name":"a.example.com"},"type":"hysteria","up_mbps":20}`,
		},
		{
			"anytls",
			"anytls://pw@1.2.3.4:443?sni=a.example.com&fp=chrome#a",
			`{"password":"pw","server":"1.2.3.4","server_port":443,"tls":{"enabled":true,"server_name":"a.example.com","utls":{"enabled":true,"fingerprint":"chrome"}},"type":"anytls"}`,
		},
		{
			"naive",
			"naive+https://u:p@1.2.3.4:443#n",
			`{"password":"p","server":"1.2.3.4","server_port":443,"tls":{"enabled":true,"server_name":"1.2.3.4"},"type":"naive","username":"u"}`,
		},
		{
			"ssh",
			"ssh://root:pw@1.2.3.4#s",
			`{"password":"pw","server":"1.2.3.4","server_port":22,"type":"ssh","user":"root"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseLink(tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if got := mustJSON(t, singboxObj(t, res)); got != tc.want {
				t.Errorf("outbound = %s\nwant      %s", got, tc.want)
			}
			if _, hasTag := singboxObj(t, res)["tag"]; hasTag {
				t.Error("sing-box object must not carry a tag key")
			}
		})
	}
	if _, err := ParseLink("hysteria://1.2.3.4:443?protocol=faketcp#x"); err == nil {
		t.Error("hysteria v1 faketcp must be rejected")
	}
}

// The four configurations users import most must keep their exact shape.
func TestParseTypicalVlessConfigs(t *testing.T) {
	tests := []struct {
		name, link, stream string
	}{
		{
			"reality tcp",
			"vless://u1@1.2.3.4:443?type=tcp&security=reality&pbk=PUB&fp=chrome&sni=a.com&sid=ab&spx=%2F&flow=xtls-rprx-vision#r",
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","mldsa65Verify":"","publicKey":"PUB","serverName":"a.com","shortId":"ab","spiderX":"/"},"security":"reality","tcpSettings":{"header":{"type":"none"}}}`,
		},
		{
			"ws tls",
			"vless://u1@1.2.3.4:443?type=ws&security=tls&sni=a.com&host=a.com&path=%2Fws%3Fed%3D2048&fp=chrome&alpn=h2%2Chttp%2F1.1#w",
			`{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"echConfigList":"","fingerprint":"chrome","pinnedPeerCertSha256":"","serverName":"a.com","verifyPeerCertByName":""},"wsSettings":{"headers":{},"heartbeatPeriod":0,"host":"a.com","path":"/ws?ed=2048"}}`,
		},
		{
			"ws none",
			"vless://u1@1.2.3.4:80?type=ws&security=none&host=a.com&path=%2F#n",
			`{"network":"ws","security":"none","wsSettings":{"headers":{},"heartbeatPeriod":0,"host":"a.com","path":"/"}}`,
		},
		{
			"xhttp reality",
			"vless://u1@1.2.3.4:443?type=xhttp&security=reality&pbk=PUB&fp=chrome&sni=a.com&sid=ab&path=%2Fx&mode=packet-up&host=a.com#x",
			`{"network":"xhttp","realitySettings":{"fingerprint":"chrome","mldsa65Verify":"","publicKey":"PUB","serverName":"a.com","shortId":"ab","spiderX":""},"security":"reality","xhttpSettings":{"headers":{},"host":"a.com","mode":"packet-up","path":"/x","xPaddingBytes":"100-1000"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseLink(tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if got := mustJSON(t, res.Outbound["streamSettings"]); got != tc.stream {
				t.Errorf("streamSettings = %s\nwant            %s", got, tc.stream)
			}
		})
	}
}

func TestParseSubscriptionReportsSkippedLines(t *testing.T) {
	body := "vless://u1@1.2.3.4:443?type=tcp&security=none#ok\n" +
		"# comment\n" +
		"warp://something-unknown-and-quite-long-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
		"https://example.com/page\n"
	sub := ParseSubscription([]byte(body))
	if len(sub.Outbounds) != 1 || len(sub.Skipped) != 2 {
		t.Fatalf("outbounds=%d skipped=%d", len(sub.Outbounds), len(sub.Skipped))
	}
	if got := len([]rune(sub.Skipped[0].Line)); got != 80 {
		t.Errorf("skipped line length = %d, want 80", got)
	}
	want := []Skipped{
		{Line: sub.Skipped[0].Line, Reason: "unsupported link scheme"},
		{Line: "https://example.com/page", Reason: "http proxy link needs an explicit port"},
	}
	if !reflect.DeepEqual(sub.Skipped, want) {
		t.Errorf("skipped = %+v, want %+v", sub.Skipped, want)
	}
}
