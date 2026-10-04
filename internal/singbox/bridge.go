// Package singbox runs a sing-box sidecar for outbound protocols xray-core lacks
// and bridges each one into the xray config as a loopback SOCKS outbound.
package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// Protocol is the panel pseudo-protocol; settings.outbound holds a sing-box outbound object.
const Protocol = "singbox"

const (
	portMin = 21000
	portMax = 21999
)

func IsSingboxOutbound(raw []byte) bool {
	var probe struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return strings.EqualFold(probe.Protocol, Protocol)
}

// ValidateOutbound checks a "singbox" pseudo-outbound without the xray loader.
func ValidateOutbound(raw []byte) error {
	_, err := parseOutbound(raw)
	return err
}

type parsed struct {
	Tag      string
	Outbound map[string]json.RawMessage
}

func parseOutbound(raw []byte) (*parsed, error) {
	var env struct {
		Tag      string `json:"tag"`
		Settings struct {
			Outbound map[string]json.RawMessage `json:"outbound"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("singbox outbound is not valid JSON: %w", err)
	}
	ob := env.Settings.Outbound
	if ob == nil {
		return nil, errors.New("singbox outbound: settings.outbound is missing")
	}
	var typ, server string
	var port int
	if json.Unmarshal(ob["type"], &typ) != nil || strings.TrimSpace(typ) == "" {
		return nil, errors.New("singbox outbound: settings.outbound.type must be a non-empty string")
	}
	if json.Unmarshal(ob["server"], &server) != nil || strings.TrimSpace(server) == "" {
		return nil, errors.New("singbox outbound: settings.outbound.server must be a non-empty string")
	}
	if json.Unmarshal(ob["server_port"], &port) != nil || port < 1 || port > 65535 {
		return nil, errors.New("singbox outbound: settings.outbound.server_port must be an integer 1-65535")
	}
	return &parsed{Tag: env.Tag, Outbound: ob}, nil
}

var (
	portsMu     sync.Mutex
	assigned    = map[string]int{}
	sidecarSync = apply
	binaryReady = func() bool { _, err := os.Stat(GetBinaryPath()); return err == nil }
)

// allocatePorts keeps a tag on its port across calls; new tags start at a hash of the tag.
func allocatePorts(tags []string) (map[string]int, error) {
	portsMu.Lock()
	defer portsMu.Unlock()
	if len(tags) > portMax-portMin+1 {
		return nil, errors.New("too many singbox outbounds for the loopback port range")
	}
	next := make(map[string]int, len(tags))
	used := make(map[int]bool, len(tags))
	for _, tag := range tags {
		if p, ok := assigned[tag]; ok && !used[p] {
			next[tag] = p
			used[p] = true
		}
	}
	for _, tag := range tags {
		if _, ok := next[tag]; ok {
			continue
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(tag))
		p := portMin + int(h.Sum32()%uint32(portMax-portMin+1))
		for used[p] {
			p++
			if p > portMax {
				p = portMin
			}
		}
		next[tag] = p
		used[p] = true
	}
	assigned = next
	return next, nil
}

type socksReplacement struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings struct {
		Servers []socksServer `json:"servers"`
	} `json:"settings"`
}

type socksServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func replacementFor(tag string, port int) socksReplacement {
	r := socksReplacement{Tag: tag, Protocol: "socks"}
	r.Settings.Servers = []socksServer{{Address: "127.0.0.1", Port: port}}
	return r
}

// buildConfig renders the sing-box config: one mixed inbound per tag routed to its outbound.
func buildConfig(outbounds map[string]map[string]json.RawMessage, ports map[string]int) ([]byte, error) {
	tags := make([]string, 0, len(outbounds))
	for tag := range outbounds {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var inbounds, outs, rules []any
	for _, tag := range tags {
		inTag := "in-" + tag
		inbounds = append(inbounds, map[string]any{
			"type": "mixed", "tag": inTag, "listen": "127.0.0.1", "listen_port": ports[tag],
		})
		ob := make(map[string]json.RawMessage, len(outbounds[tag])+1)
		for k, v := range outbounds[tag] {
			ob[k] = v
		}
		tagJSON, _ := json.Marshal(tag)
		ob["tag"] = tagJSON
		outs = append(outs, ob)
		rules = append(rules, map[string]any{"inbound": []string{inTag}, "action": "route", "outbound": tag})
	}
	return json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": outs,
		"route":     map[string]any{"rules": rules},
	}, "", "  ")
}

// Bridge replaces every "singbox" outbound in cfg with a loopback SOCKS outbound
// (same tag) and (re)starts the sidecar with the matching config.
func Bridge(cfg *xray.Config) error {
	var entries []json.RawMessage
	if len(cfg.OutboundConfigs) > 0 {
		if err := json.Unmarshal(cfg.OutboundConfigs, &entries); err != nil {
			return nil
		}
	}
	valid := map[string]map[string]json.RawMessage{}
	for _, raw := range entries {
		if !IsSingboxOutbound(raw) {
			continue
		}
		p, err := parseOutbound(raw)
		if err == nil && p.Tag == "" {
			err = errors.New("outbound has no tag")
		}
		if err != nil {
			logger.Warning("singbox: dropping outbound:", err)
			continue
		}
		valid[p.Tag] = p.Outbound
	}
	if len(valid) > 0 && !binaryReady() {
		logger.Warning("singbox: binary not found at", GetBinaryPath(), "- dropping", len(valid), "singbox outbound(s)")
		valid = map[string]map[string]json.RawMessage{}
	}

	var ports map[string]int
	var conf []byte
	if len(valid) > 0 {
		tags := make([]string, 0, len(valid))
		for tag := range valid {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		var err error
		if ports, err = allocatePorts(tags); err != nil {
			logger.Warning("singbox:", err)
			valid, ports = map[string]map[string]json.RawMessage{}, nil
		} else if conf, err = buildConfig(valid, ports); err != nil {
			return err
		}
	} else {
		_, _ = allocatePorts(nil)
	}
	if err := sidecarSync(conf); err != nil {
		logger.Warning("singbox: sidecar start failed, dropping outbounds:", err)
		valid = map[string]map[string]json.RawMessage{}
	}

	out := make([]json.RawMessage, 0, len(entries))
	for _, raw := range entries {
		if !IsSingboxOutbound(raw) {
			out = append(out, raw)
			continue
		}
		var tag struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &tag)
		if _, ok := valid[tag.Tag]; !ok {
			// Keep the tag alive as blackhole so routing rules naming it still load.
			if tag.Tag != "" {
				b, _ := json.Marshal(map[string]any{"tag": tag.Tag, "protocol": "blackhole"})
				out = append(out, b)
			}
			continue
		}
		b, _ := json.Marshal(replacementFor(tag.Tag, ports[tag.Tag]))
		out = append(out, b)
	}
	if len(entries) == 0 {
		return nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	cfg.OutboundConfigs = b
	return nil
}

// BridgeLive rewrites singbox outbounds in a side config (e.g. the outbound
// tester) to the live sidecar's ports without touching the sidecar.
func BridgeLive(outbounds []any) []any {
	portsMu.Lock()
	live := make(map[string]int, len(assigned))
	for tag, p := range assigned {
		live[tag] = p
	}
	portsMu.Unlock()
	sidecarMu.Lock()
	running := sidecarProc != nil && sidecarProc.IsRunning()
	sidecarMu.Unlock()

	out := make([]any, 0, len(outbounds))
	for _, ob := range outbounds {
		m, ok := ob.(map[string]any)
		p, _ := m["protocol"].(string)
		if !ok || !strings.EqualFold(p, Protocol) {
			out = append(out, ob)
			continue
		}
		tag, _ := m["tag"].(string)
		if port, ok := live[tag]; ok && running {
			out = append(out, replacementFor(tag, port))
			continue
		}
		// Unsaved or not running: keep the tag valid so the rest of the batch starts.
		out = append(out, map[string]any{"tag": tag, "protocol": "blackhole"})
	}
	return out
}
