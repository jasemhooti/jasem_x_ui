package fragment

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestEnsure(t *testing.T) {
	chained := `{"tag":"a","protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"jasem-fragment"}}}`
	plain := `{"tag":"direct","protocol":"freedom"}`
	custom := `{"tag":"jasem-fragment","protocol":"freedom","settings":{"fragment":{"packets":"1-3"}}}`
	tests := []struct {
		name      string
		outbounds string
		wantTags  []string
	}{
		{"no reference leaves config alone", "[" + plain + "]", []string{"direct"}},
		{"reference appends default", "[" + plain + "," + chained + "]", []string{"direct", "a", Tag}},
		{"user-defined fragment outbound wins", "[" + chained + "," + custom + "]", []string{"a", Tag}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &xray.Config{OutboundConfigs: []byte(tt.outbounds)}
			if err := Ensure(cfg); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			var got []map[string]any
			if err := json.Unmarshal(cfg.OutboundConfigs, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(got) != len(tt.wantTags) {
				t.Fatalf("got %d outbounds, want %d", len(got), len(tt.wantTags))
			}
			for i, tag := range tt.wantTags {
				if got[i]["tag"] != tag {
					t.Fatalf("outbound %d tag = %v, want %s", i, got[i]["tag"], tag)
				}
			}
			if tt.name == "user-defined fragment outbound wins" {
				frag := got[1]["settings"].(map[string]any)["fragment"].(map[string]any)
				if frag["packets"] != "1-3" {
					t.Fatalf("custom fragment overwritten: %v", frag)
				}
			}
		})
	}
}
