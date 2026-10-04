// Package jasem is the single entry point for jasem_x_ui changes to the
// generated xray config; see JASEM_SPEC.md for ownership of each step.
package jasem

import (
	"github.com/mhsanaei/3x-ui/v3/internal/jasem/compat"
	"github.com/mhsanaei/3x-ui/v3/internal/jasem/fragment"
	"github.com/mhsanaei/3x-ui/v3/internal/singbox"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// PostProcessXrayConfig runs last in XrayService.GetXrayConfig. Order matters:
// fragment and sing-box emit current-core keys that compat may then downgrade.
func PostProcessXrayConfig(cfg *xray.Config) error {
	if err := fragment.Ensure(cfg); err != nil {
		return err
	}
	if err := singbox.Bridge(cfg); err != nil {
		return err
	}
	return compat.Apply(cfg)
}
