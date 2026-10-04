package outbound

import (
	"encoding/json"
	"testing"
)

// A singbox or fragment-chained outbound must not keep the temp core from starting.
func TestBuildBatchTestConfigRewritesJasemOutbounds(t *testing.T) {
	vless := map[string]any{
		"tag": "v", "protocol": "vless",
		"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "jasem-fragment"}},
	}
	tuic := map[string]any{
		"tag": "t", "protocol": "singbox",
		"settings": map[string]any{"outbound": map[string]any{"type": "tuic", "server": "a.example", "server_port": 443}},
	}
	items := []*httpBatchItem{{tag: "v", outbound: vless, result: &TestOutboundResult{}}}
	cfg := buildBatchTestConfig(items, []any{tuic}, []int{20001})

	var got []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	protocols := map[string]string{}
	for _, ob := range got {
		protocols[ob["tag"].(string)], _ = ob["protocol"].(string)
	}
	want := map[string]string{"t": "blackhole", "v": "vless", "jasem-fragment": "freedom"}
	for tag, proto := range want {
		if protocols[tag] != proto {
			t.Fatalf("outbound %q protocol = %q, want %q (all: %v)", tag, protocols[tag], proto, protocols)
		}
	}
}
