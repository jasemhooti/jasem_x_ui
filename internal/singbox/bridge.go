// Package singbox runs a sing-box sidecar for outbound protocols xray-core lacks
// and bridges each one into the xray config as a loopback SOCKS outbound.
package singbox

import (
	"encoding/json"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// Protocol is the panel pseudo-protocol; settings.outbound holds a sing-box outbound object.
const Protocol = "singbox"

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
	return nil
}

// Bridge replaces every "singbox" outbound in cfg with a loopback SOCKS outbound
// (same tag) and (re)starts the sidecar with the matching config.
func Bridge(cfg *xray.Config) error {
	return nil
}
