package compat

import (
	"fmt"
	"os"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func binaryStatKey() string {
	p := xray.GetBinaryPath()
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d", p, st.Size(), st.ModTime().UnixNano())
}
