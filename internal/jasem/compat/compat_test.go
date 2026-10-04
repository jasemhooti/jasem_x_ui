package compat

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func setVersion(t *testing.T, v string) {
	t.Helper()
	oldDetect, oldStat := detectCoreV, statKey
	detectCoreV = func() string { return v }
	statKey = func() string { return "" }
	t.Cleanup(func() { detectCoreV, statKey = oldDetect, oldStat })
}

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad json %s: %v", s, err)
	}
	return v
}

func TestApply(t *testing.T) {
	hopIn := `{"network":"hysteria","finalmask":{"udp":[
		{"type":"salamander","settings":{"password":"p"}},
		{"type":"udphop","settings":{"mode":"intervalremote","remotePorts":"20000-30000","interval":"5-10"}}]}}`
	hopOut := `{"network":"hysteria","finalmask":{"udp":[
		{"type":"salamander","settings":{"password":"p"}}],
		"quicParams":{"udpHop":{"ports":"20000-30000","interval":"5-10"}}}}`
	tests := []struct {
		name       string
		version    string
		stream     string
		wantStream string
		outbound   string
		wantOut    string
		routing    string
		wantRoute  string
	}{
		{name: "udphop mask to quicParams on old core", version: "26.6.27", stream: hopIn, wantStream: hopOut},
		{name: "udphop untouched on new core", version: "26.9.9", stream: hopIn, wantStream: hopIn},
		{name: "unknown newer core untouched", version: "26.9.30", stream: hopIn, wantStream: hopIn},
		{
			name: "udphop with local mode dropped alone", version: "26.6.27",
			stream:     `{"finalmask":{"udp":[{"type":"udphop","settings":{"mode":"intervallocal","remotePorts":"1-2"}}]}}`,
			wantStream: `{}`,
		},
		{
			name: "xmc tcp mask dropped, others kept", version: "26.6.27",
			stream:     `{"finalmask":{"tcp":[{"type":"xmc","settings":{}},{"type":"fragment","settings":{"packets":"1-3"}}]}}`,
			wantStream: `{"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"1-3"}}]}}`,
		},
		{
			name: "method alias becomes network", version: "26.6.27",
			stream:     `{"method":"xhttp","network":"tcp","security":"none"}`,
			wantStream: `{"network":"xhttp","security":"none"}`,
		},
		{
			name: "outbound stream rewritten", version: "26.6.27",
			outbound: `[{"tag":"o1","protocol":"vless","streamSettings":` + hopIn + `},{"tag":"d","protocol":"freedom"}]`,
			wantOut:  `[{"tag":"o1","protocol":"vless","streamSettings":` + hopOut + `},{"tag":"d","protocol":"freedom"}]`,
		},
		{
			name: "localOS rule dropped", version: "26.6.27",
			routing:   `{"rules":[{"ruleTag":"a","localOS":["windows"],"outboundTag":"x"},{"ruleTag":"b","outboundTag":"y"}]}`,
			wantRoute: `{"rules":[{"ruleTag":"b","outboundTag":"y"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setVersion(t, tc.version)
			cfg := &xray.Config{}
			if tc.stream != "" {
				cfg.InboundConfigs = []xray.InboundConfig{{Tag: "in", StreamSettings: []byte(tc.stream)}}
			}
			cfg.OutboundConfigs = []byte(tc.outbound)
			cfg.RouterConfig = []byte(tc.routing)
			if err := Apply(cfg); err != nil {
				t.Fatal(err)
			}
			check := func(what string, got []byte, want string) {
				t.Helper()
				if want == "" {
					return
				}
				if !reflect.DeepEqual(mustJSON(t, string(got)), mustJSON(t, want)) {
					t.Errorf("%s:\n got  %s\n want %s", what, got, want)
				}
			}
			if tc.stream != "" {
				check("stream", cfg.InboundConfigs[0].StreamSettings, tc.wantStream)
			}
			check("outbounds", cfg.OutboundConfigs, tc.wantOut)
			check("routing", cfg.RouterConfig, tc.wantRoute)
		})
	}
}

func TestParseVersionOutput(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Xray 26.6.27 (Xray, Penetrates Everything.) 1a2b3c (go1.26 linux/amd64)\n", "26.6.27"},
		{"Xray v26.9.9 (x)", "26.9.9"},
		{"garbage", ""},
		{"Xray dev (x)", ""},
	}
	for _, tc := range tests {
		if got := parseVersionOutput(tc.in); got != tc.want {
			t.Errorf("parseVersionOutput(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCoreVersionCachesAndFallsBack(t *testing.T) {
	oldDetect, oldStat := detectCoreV, statKey
	t.Cleanup(func() { detectCoreV, statKey = oldDetect, oldStat; versionKey = "" })
	calls := 0
	detectCoreV = func() string { calls++; return "26.9.9" }
	statKey = func() string { return "bin|1" }
	versionKey = ""
	if CoreVersion() != "26.9.9" || CoreVersion() != "26.9.9" || calls != 1 {
		t.Errorf("want one cached detection, got %d calls", calls)
	}
	statKey = func() string { return "bin|2" }
	CoreVersion()
	if calls != 2 {
		t.Errorf("binary change must re-detect, calls=%d", calls)
	}
	detectCoreV = func() string { return "" }
	statKey = func() string { return "" }
	if got := CoreVersion(); got != DefaultCoreVersion {
		t.Errorf("fallback = %q, want %q", got, DefaultCoreVersion)
	}
}
