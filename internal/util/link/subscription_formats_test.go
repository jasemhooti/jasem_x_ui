package link

import "testing"

const clashBody = `
port: 7890
proxies:
  - name: "reality-node"
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: a.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PUB
      short-id: ab
  - name: "ws-node"
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    network: ws
    tls: true
    servername: a.example.com
    ws-opts:
      path: /ws
      headers:
        Host: a.example.com
  - name: "trojan-node"
    type: trojan
    server: 1.2.3.4
    port: 443
    password: pw
    sni: a.example.com
  - name: "tuic-node"
    type: tuic
    server: 1.2.3.4
    port: 443
    uuid: 11111111-2222-4333-8444-555555555555
    password: pw
    sni: a.example.com
    alpn: [h3]
    congestion-controller: bbr
  - name: "sock"
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: alice
    password: secret
  - name: "wg"
    type: wireguard
    server: 1.2.3.4
    port: 51820
proxy-groups:
  - name: auto
    type: select
    proxies: [reality-node]
`

func TestParseSubscriptionClashYAML(t *testing.T) {
	sub := ParseSubscription([]byte(clashBody))
	if len(sub.Outbounds) != 5 {
		t.Fatalf("outbounds = %d, want 5 (skipped %+v)", len(sub.Outbounds), sub.Skipped)
	}
	wantSkipped := []Skipped{{Line: "wg", Reason: `unsupported clash proxy type "wireguard"`}}
	if len(sub.Skipped) != 1 || sub.Skipped[0] != wantSkipped[0] {
		t.Errorf("skipped = %+v, want %+v", sub.Skipped, wantSkipped)
	}
	reality := sub.Outbounds[0]
	if reality["tag"] != "reality-node" || reality["protocol"] != "vless" {
		t.Fatalf("first outbound = %v", reality)
	}
	wantStream := `{"network":"tcp","realitySettings":{"fingerprint":"chrome","mldsa65Verify":"","publicKey":"PUB","serverName":"a.example.com","shortId":"ab","spiderX":""},"security":"reality","tcpSettings":{"header":{"type":"none"}}}`
	if got := mustJSON(t, reality["streamSettings"]); got != wantStream {
		t.Errorf("reality stream = %s\nwant           %s", got, wantStream)
	}
	if got := mustJSON(t, reality["settings"]); got != `{"address":"1.2.3.4","encryption":"none","flow":"xtls-rprx-vision","id":"11111111-2222-4333-8444-555555555555","port":443}` {
		t.Errorf("reality settings = %s", got)
	}
	wantWS := `{"network":"ws","security":"tls","tlsSettings":{"alpn":[],"echConfigList":"","fingerprint":"","pinnedPeerCertSha256":"","serverName":"a.example.com","verifyPeerCertByName":""},"wsSettings":{"headers":{},"heartbeatPeriod":0,"host":"a.example.com","path":"/ws"}}`
	if got := mustJSON(t, sub.Outbounds[1]["streamSettings"]); got != wantWS {
		t.Errorf("ws stream = %s\nwant       %s", got, wantWS)
	}
	tuic := singboxObj(t, &ParseResult{Outbound: sub.Outbounds[3]})
	if tuic["type"] != "tuic" || tuic["congestion_control"] != "bbr" || tuic["password"] != "pw" {
		t.Errorf("tuic = %v", tuic)
	}
	if sub.Outbounds[4]["protocol"] != "socks" {
		t.Errorf("socks5 outbound = %v", sub.Outbounds[4])
	}
}

const singboxBody = `{
  "outbounds": [
    {"type":"selector","tag":"sel","outbounds":["a"]},
    {"type":"direct","tag":"direct"},
    {"type":"vless","tag":"v","server":"1.2.3.4","server_port":443,"uuid":"u1","flow":"xtls-rprx-vision",
     "tls":{"enabled":true,"server_name":"a.com","utls":{"enabled":true,"fingerprint":"chrome"},
            "reality":{"enabled":true,"public_key":"PUB","short_id":"ab"}}},
    {"type":"vless","tag":"w","server":"1.2.3.4","server_port":443,"uuid":"u1",
     "tls":{"enabled":true,"server_name":"a.com"},"transport":{"type":"ws","path":"/ws","headers":{"Host":"a.com"}}},
    {"type":"anytls","tag":"any","server":"1.2.3.4","server_port":443,"password":"pw","tls":{"enabled":true}},
    {"type":"wireguard","tag":"wg","server":"1.2.3.4","server_port":51820}
  ]
}`

func TestParseSubscriptionSingboxJSON(t *testing.T) {
	sub := ParseSubscription([]byte(singboxBody))
	if len(sub.Outbounds) != 3 {
		t.Fatalf("outbounds = %d (skipped %+v)", len(sub.Outbounds), sub.Skipped)
	}
	if len(sub.Skipped) != 1 || sub.Skipped[0].Reason != `unsupported sing-box outbound type "wireguard"` {
		t.Errorf("skipped = %+v", sub.Skipped)
	}
	wantStream := `{"network":"tcp","realitySettings":{"fingerprint":"chrome","mldsa65Verify":"","publicKey":"PUB","serverName":"a.com","shortId":"ab","spiderX":""},"security":"reality","tcpSettings":{"header":{"type":"none"}}}`
	if got := mustJSON(t, sub.Outbounds[0]["streamSettings"]); got != wantStream {
		t.Errorf("reality stream = %s", got)
	}
	ws := sub.Outbounds[1]["streamSettings"].(map[string]any)["wsSettings"]
	if got := mustJSON(t, ws); got != `{"headers":{},"heartbeatPeriod":0,"host":"a.com","path":"/ws"}` {
		t.Errorf("ws settings = %s", got)
	}
	anytls := singboxObj(t, &ParseResult{Outbound: sub.Outbounds[2]})
	if got := mustJSON(t, anytls); got != `{"password":"pw","server":"1.2.3.4","server_port":443,"tls":{"enabled":true},"type":"anytls"}` {
		t.Errorf("anytls passthrough = %s", got)
	}
	if sub.Outbounds[2]["tag"] != "any" {
		t.Errorf("tag = %v", sub.Outbounds[2]["tag"])
	}
}

const xrayBody = `[
  {"remarks":"Node A","outbounds":[
    {"tag":"proxy","protocol":"vless","settings":{"address":"1.2.3.4","port":443,"id":"u1","encryption":"none"},
     "streamSettings":{"network":"tcp","security":"none"}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}]},
  {"remarks":"Node B","outbounds":[
    {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"5.6.7.8","port":443,"password":"pw"}]}},
    {"tag":"odd","protocol":"mystery"}]}
]`

func TestParseSubscriptionXrayJSON(t *testing.T) {
	sub := ParseSubscription([]byte(xrayBody))
	if len(sub.Outbounds) != 2 {
		t.Fatalf("outbounds = %d", len(sub.Outbounds))
	}
	if sub.Outbounds[0]["tag"] != "Node A" || sub.Outbounds[1]["tag"] != "Node B" {
		t.Errorf("tags = %v, %v", sub.Outbounds[0]["tag"], sub.Outbounds[1]["tag"])
	}
	if sub.Identities[0] == sub.Identities[1] {
		t.Error("distinct servers share an identity")
	}
	if len(sub.Skipped) != 1 || sub.Skipped[0].Reason != `unsupported xray protocol "mystery"` {
		t.Errorf("skipped = %+v", sub.Skipped)
	}
}

func TestParseSubscriptionSingleXrayConfigAndBase64(t *testing.T) {
	single := `{"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"1.1.1.1","port":1080}]}}]}`
	if sub := ParseSubscription([]byte(single)); len(sub.Outbounds) != 1 {
		t.Fatalf("single config outbounds = %d", len(sub.Outbounds))
	}
	b64 := "dmxlc3M6Ly91MUAxLjIuMy40OjQ0Mz90eXBlPXRjcCZzZWN1cml0eT1ub25lI29r" // vless://u1@1.2.3.4:443?type=tcp&security=none#ok
	sub := ParseSubscription([]byte(b64))
	if len(sub.Outbounds) != 1 || sub.Outbounds[0]["tag"] != "ok" {
		t.Fatalf("base64 body = %+v skipped %+v", sub.Outbounds, sub.Skipped)
	}
}
