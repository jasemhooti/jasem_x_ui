// Package compat rewrites the generated xray config so an older running core
// (default v26.6.27) accepts keys the panel writes for the newest core.
package compat

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// DefaultCoreVersion is the core a fresh jasem_x_ui install ships with.
const DefaultCoreVersion = "26.6.27"

// currentShapeSince is the first core that reads the shapes the panel emits.
const currentShapeSince = "26.9.9"

// Apply downgrades cfg in place for cores older than 26.9.9 and never fails;
// a piece the old core cannot express is dropped with a warning.
func Apply(cfg *xray.Config) error {
	if cfg == nil {
		return nil
	}
	if v := CoreVersion(); versionLess(v, currentShapeSince) == 1 {
		downgradeConfig(cfg)
	}
	return nil
}

func downgradeConfig(cfg *xray.Config) {
	for i := range cfg.InboundConfigs {
		in := &cfg.InboundConfigs[i]
		if out, ok := rewriteStreamJSON(in.StreamSettings, "inbound "+in.Tag); ok {
			in.StreamSettings = out
		}
	}
	if out, ok := rewriteOutbounds(cfg.OutboundConfigs); ok {
		cfg.OutboundConfigs = out
	}
	if out, ok := rewriteRouting(cfg.RouterConfig); ok {
		cfg.RouterConfig = out
	}
}

func rewriteStreamJSON(raw []byte, label string) ([]byte, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var stream map[string]any
	if json.Unmarshal(raw, &stream) != nil || !downgradeStream(stream, label) {
		return nil, false
	}
	out, err := json.Marshal(stream)
	return out, err == nil
}

func rewriteOutbounds(raw []byte) ([]byte, bool) {
	var outbounds []any
	if len(raw) == 0 || json.Unmarshal(raw, &outbounds) != nil {
		return nil, false
	}
	changed := false
	for _, ob := range outbounds {
		obj, _ := ob.(map[string]any)
		stream, _ := obj["streamSettings"].(map[string]any)
		if stream == nil {
			continue
		}
		tag, _ := obj["tag"].(string)
		if downgradeStream(stream, "outbound "+tag) {
			changed = true
		}
	}
	if !changed {
		return nil, false
	}
	out, err := json.Marshal(outbounds)
	return out, err == nil
}

// rewriteRouting drops rules using localOS: the old core ignores the key and
// would apply the rule on every OS.
func rewriteRouting(raw []byte) ([]byte, bool) {
	var routing map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &routing) != nil {
		return nil, false
	}
	rules, _ := routing["rules"].([]any)
	kept := make([]any, 0, len(rules))
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		if v, present := rule["localOS"]; present && v != nil {
			logger.Warningf("compat: dropping routing rule %v, localOS needs xray-core >= %s", rule["ruleTag"], currentShapeSince)
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == len(rules) {
		return nil, false
	}
	routing["rules"] = kept
	out, err := json.Marshal(routing)
	return out, err == nil
}

func downgradeStream(stream map[string]any, label string) bool {
	changed := false
	if method, ok := stream["method"]; ok {
		// "method" aliases "network" and wins, but only new cores read it.
		if method != nil {
			stream["network"] = method
		}
		delete(stream, "method")
		changed = true
	}
	fm, _ := stream["finalmask"].(map[string]any)
	if fm == nil {
		return changed
	}
	if downgradeFinalmask(fm, label) {
		changed = true
		if len(fm) == 0 {
			delete(stream, "finalmask")
		}
	}
	return changed
}

func downgradeFinalmask(fm map[string]any, label string) bool {
	changed := false
	if masks, ok := fm["tcp"].([]any); ok {
		kept := dropMasks(masks, "xmc", label, func(map[string]any) bool { return false })
		if len(kept) != len(masks) {
			changed = true
			setOrDelete(fm, "tcp", kept)
		}
	}
	if masks, ok := fm["udp"].([]any); ok {
		kept := dropMasks(masks, "udphop", label, func(m map[string]any) bool { return hopToQuicParams(fm, m) })
		if len(kept) != len(masks) {
			changed = true
			setOrDelete(fm, "udp", kept)
		}
	}
	return changed
}

// dropMasks removes masks of one type; convert may rescue a mask by returning true.
func dropMasks(masks []any, typ, label string, convert func(map[string]any) bool) []any {
	kept := make([]any, 0, len(masks))
	for _, raw := range masks {
		m, _ := raw.(map[string]any)
		if t, _ := m["type"].(string); !strings.EqualFold(t, typ) {
			kept = append(kept, raw)
			continue
		}
		if !convert(m) {
			logger.Warningf("compat: %s: dropping finalmask %q mask, unsupported by xray-core < %s", label, typ, currentShapeSince)
		}
	}
	return kept
}

// hopToQuicParams maps the interval-remote udphop mask back to the old
// quicParams.udpHop, the only hopping mode the old core has.
func hopToQuicParams(fm, mask map[string]any) bool {
	s, _ := mask["settings"].(map[string]any)
	ports := s["remotePorts"]
	if ports == nil || ports == "" {
		return false
	}
	mode, _ := s["mode"].(string)
	if mode != "" && !strings.EqualFold(mode, "intervalremote") {
		return false
	}
	if ips, _ := s["remoteIPs"].([]any); len(ips) > 0 || s["sockopt"] != nil {
		return false
	}
	qp, _ := fm["quicParams"].(map[string]any)
	if qp == nil {
		qp = map[string]any{}
		fm["quicParams"] = qp
	}
	if _, exists := qp["udpHop"]; exists {
		return false
	}
	hop := map[string]any{"ports": ports}
	if s["interval"] != nil {
		hop["interval"] = s["interval"]
	}
	qp["udpHop"] = hop
	return true
}

func setOrDelete(m map[string]any, key string, v []any) {
	if len(v) == 0 {
		delete(m, key)
		return
	}
	m[key] = v
}

var (
	versionMu   sync.Mutex
	versionKey  string
	versionVal  string
	detectCoreV = runCoreVersion
	// statKey identifies the binary so a dashboard core switch re-detects.
	statKey = binaryStatKey
)

// CoreVersion returns the installed core version, cached per binary file; it
// falls back to DefaultCoreVersion when the binary cannot be queried.
func CoreVersion() string {
	key := statKey()
	versionMu.Lock()
	defer versionMu.Unlock()
	if key != "" && key == versionKey {
		return versionVal
	}
	v := detectCoreV()
	if v == "" {
		logger.Warningf("compat: cannot detect xray-core version, assuming %s", DefaultCoreVersion)
		return DefaultCoreVersion
	}
	versionKey, versionVal = key, v
	return v
}

func runCoreVersion() string {
	out, err := exec.Command(xray.GetBinaryPath(), "-version").Output()
	if err != nil {
		return ""
	}
	return parseVersionOutput(string(out))
}

// parseVersionOutput reads "Xray 26.6.27 (Xray, ...)" and returns "26.6.27".
func parseVersionOutput(out string) string {
	f := strings.Fields(out)
	if len(f) < 2 {
		return ""
	}
	if _, ok := parseVersion(f[1]); !ok {
		return ""
	}
	return strings.TrimPrefix(f[1], "v")
}

func parseVersion(v string) ([3]int, bool) {
	var r [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return r, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return r, false
		}
		r[i] = n
	}
	return r, true
}

// versionLess returns 1 when a < b, 0 when not, -1 when unparsable.
func versionLess(a, b string) int {
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)
	if !okA || !okB {
		return -1
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return 1
			}
			return 0
		}
	}
	return 0
}
