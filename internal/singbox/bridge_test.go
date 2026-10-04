package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func sb(tag, typ string, port int) string {
	return `{"tag":"` + tag + `","protocol":"singbox","settings":{"outbound":{"type":"` + typ +
		`","server":"example.com","server_port":` + itoa(port) + `,"password":"p"}}}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// stubSidecar replaces the sidecar and binary check, returning the last conf applied.
func stubSidecar(t *testing.T, binary bool) *[]byte {
	t.Helper()
	var last []byte
	oldSync, oldReady := sidecarSync, binaryReady
	sidecarSync = func(conf []byte) error { last = conf; return nil }
	binaryReady = func() bool { return binary }
	portsMu.Lock()
	assigned = map[string]int{}
	portsMu.Unlock()
	t.Cleanup(func() { sidecarSync, binaryReady = oldSync, oldReady })
	return &last
}

func bridged(t *testing.T, outs ...string) []map[string]any {
	t.Helper()
	cfg := &xray.Config{OutboundConfigs: []byte("[" + strings.Join(outs, ",") + "]")}
	if err := Bridge(cfg); err != nil {
		t.Fatalf("Bridge: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestBridgeReplacesWithSocksAndKeepsOthers(t *testing.T) {
	conf := stubSidecar(t, true)
	got := bridged(t, `{"tag":"direct","protocol":"freedom"}`, sb("tuic-1", "tuic", 443), sb("hy-1", "hysteria", 8443))
	if len(got) != 3 || got[0]["tag"] != "direct" || got[0]["protocol"] != "freedom" {
		t.Fatalf("unexpected outbounds: %v", got)
	}
	var sc struct {
		Inbounds []struct {
			Type, Tag, Listen string
			ListenPort        int `json:"listen_port"`
		}
		Outbounds []map[string]any
		Route     struct {
			Rules []struct {
				Inbound  []string
				Action   string
				Outbound string
			}
		}
	}
	if err := json.Unmarshal(*conf, &sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.Inbounds) != 2 || len(sc.Outbounds) != 2 || len(sc.Route.Rules) != 2 {
		t.Fatalf("sing-box config shape wrong: %s", *conf)
	}
	for i, tag := range []string{"tuic-1", "hy-1"} {
		out := got[i+1]
		if out["tag"] != tag || out["protocol"] != "socks" {
			t.Fatalf("outbound %d not replaced: %v", i, out)
		}
		srv := out["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		port := int(srv["port"].(float64))
		if srv["address"] != "127.0.0.1" || port < portMin || port > portMax {
			t.Fatalf("bad socks server for %s: %v", tag, srv)
		}
		var in = sc.Inbounds[0]
		var rule = sc.Route.Rules[0]
		var ob = sc.Outbounds[0]
		if tag == "tuic-1" { // sorted by tag: hy-1 first
			in, rule, ob = sc.Inbounds[1], sc.Route.Rules[1], sc.Outbounds[1]
		}
		if in.Type != "mixed" || in.Listen != "127.0.0.1" || in.ListenPort != port || in.Tag != "in-"+tag {
			t.Fatalf("inbound for %s: %+v want port %d", tag, in, port)
		}
		if rule.Action != "route" || rule.Outbound != tag || len(rule.Inbound) != 1 || rule.Inbound[0] != in.Tag {
			t.Fatalf("rule for %s: %+v", tag, rule)
		}
		if ob["tag"] != tag || ob["type"] == nil || ob["password"] != "p" {
			t.Fatalf("sing-box outbound for %s: %v", tag, ob)
		}
	}
}

func TestBridgePortsStableAndSidecarStoppedWhenNone(t *testing.T) {
	conf := stubSidecar(t, true)
	portOf := func(got []map[string]any, tag string) float64 {
		for _, o := range got {
			if o["tag"] == tag {
				return o["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["port"].(float64)
			}
		}
		t.Fatalf("tag %s missing", tag)
		return 0
	}
	first := portOf(bridged(t, sb("a", "tuic", 1), sb("b", "tuic", 2)), "b")
	second := portOf(bridged(t, sb("c", "tuic", 3), sb("b", "tuic", 2)), "b")
	if first != second {
		t.Fatalf("port for b moved: %v -> %v", first, second)
	}
	if got := bridged(t, `{"tag":"direct","protocol":"freedom"}`); len(got) != 1 || *conf != nil {
		t.Fatalf("expected sidecar stop (nil conf), got %s", *conf)
	}
}

func TestBridgeCollidingTagsGetDistinctPorts(t *testing.T) {
	stubSidecar(t, true)
	var outs []string
	for i := 0; i < 300; i++ {
		outs = append(outs, sb("t"+itoa(i), "tuic", 1))
	}
	seen := map[float64]bool{}
	for _, o := range bridged(t, outs...) {
		p := o["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["port"].(float64)
		if seen[p] {
			t.Fatalf("port %v assigned twice", p)
		}
		seen[p] = true
	}
}

func TestBridgeMissingBinaryBlackholesOutbounds(t *testing.T) {
	conf := stubSidecar(t, false)
	got := bridged(t, `{"tag":"direct","protocol":"freedom"}`, sb("tuic-1", "tuic", 443))
	if len(got) != 2 || got[1]["tag"] != "tuic-1" || got[1]["protocol"] != "blackhole" || *conf != nil {
		t.Fatalf("outbounds %v conf %s", got, *conf)
	}
}

func TestValidateOutbound(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"ok", sb("x", "tuic", 443), ""},
		{"no outbound", `{"tag":"x","protocol":"singbox","settings":{}}`, "settings.outbound is missing"},
		{"no type", `{"tag":"x","settings":{"outbound":{"server":"a","server_port":1}}}`, "type must be"},
		{"no server", `{"tag":"x","settings":{"outbound":{"type":"tuic","server_port":1}}}`, "server must be"},
		{"bad port", `{"tag":"x","settings":{"outbound":{"type":"tuic","server":"a","server_port":70000}}}`, "server_port must be"},
		{"string port", `{"tag":"x","settings":{"outbound":{"type":"tuic","server":"a","server_port":"1"}}}`, "server_port must be"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateOutbound([]byte(c.raw))
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want containing %q", err, c.want)
			}
		})
	}
}
