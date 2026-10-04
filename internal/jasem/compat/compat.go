// Package compat rewrites the generated xray config so an older running core
// (default v26.6.27) accepts keys the panel writes for the newest core.
package compat

import "github.com/mhsanaei/3x-ui/v3/internal/xray"

// DefaultCoreVersion is the core a fresh jasem_x_ui install ships with.
const DefaultCoreVersion = "26.6.27"

func Apply(cfg *xray.Config) error {
	return nil
}
