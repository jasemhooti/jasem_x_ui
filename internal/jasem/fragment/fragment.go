// Package fragment provides the shared TLS-fragment freedom outbound that other
// outbounds chain through via streamSettings.sockopt.dialerProxy.
package fragment

import "github.com/mhsanaei/3x-ui/v3/internal/xray"

const Tag = "jasem-fragment"

// Ensure appends the fragment outbound when something references Tag and the
// template does not already define its own outbound with that tag.
func Ensure(cfg *xray.Config) error {
	return nil
}
