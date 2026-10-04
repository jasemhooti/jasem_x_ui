// Package fragment provides the shared TLS-fragment freedom outbound that other
// outbounds chain through via streamSettings.sockopt.dialerProxy.
package fragment

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

const Tag = "jasem-fragment"

func defaultOutbound() map[string]any {
	return map[string]any{
		"tag":      Tag,
		"protocol": "freedom",
		"settings": map[string]any{
			"fragment": map[string]any{
				"packets":  "tlshello",
				"length":   "100-200",
				"interval": "10-20",
			},
		},
	}
}

// Ensure appends the fragment outbound when something references Tag and the
// template does not already define its own outbound with that tag.
func Ensure(cfg *xray.Config) error {
	if len(cfg.OutboundConfigs) == 0 {
		return nil
	}
	var outbounds []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		return nil
	}
	referenced := false
	for _, ob := range outbounds {
		if tag, _ := ob["tag"].(string); tag == Tag {
			return nil
		}
		if dialerProxyOf(ob) == Tag {
			referenced = true
		}
	}
	if !referenced {
		return nil
	}
	outbounds = append(outbounds, defaultOutbound())
	raw, err := json.MarshalIndent(outbounds, "", "  ")
	if err != nil {
		return err
	}
	cfg.OutboundConfigs = json_util.RawMessage(raw)
	return nil
}

func dialerProxyOf(ob map[string]any) string {
	stream, _ := ob["streamSettings"].(map[string]any)
	sockopt, _ := stream["sockopt"].(map[string]any)
	proxy, _ := sockopt["dialerProxy"].(string)
	return proxy
}
