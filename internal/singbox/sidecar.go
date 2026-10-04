package singbox

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

func GetBinaryName() string {
	name := fmt.Sprintf("sing-box-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func GetBinaryPath() string {
	return filepath.Join(config.GetBinFolderPath(), GetBinaryName())
}

func ConfigDir() string {
	return filepath.Join(config.GetBinFolderPath(), "singbox")
}

func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

var (
	sidecarMu   sync.Mutex
	sidecarProc *process
	sidecarConf []byte
	strayOnce   sync.Once
)

// apply runs the sidecar with conf, restarting only when conf changed or the
// process died; an empty conf stops it.
func apply(conf []byte) error {
	sidecarMu.Lock()
	defer sidecarMu.Unlock()
	strayOnce.Do(func() {
		if n := killStraySingboxProcesses(GetBinaryPath()); n > 0 {
			logger.Warningf("singbox: terminated %d orphaned sing-box process(es) from a previous run", n)
		}
	})
	if len(conf) == 0 {
		stopLocked()
		return nil
	}
	if sidecarProc != nil && sidecarProc.IsRunning() && bytes.Equal(sidecarConf, conf) {
		return nil
	}
	stopLocked()
	if err := os.MkdirAll(ConfigDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(ConfigPath(), conf, 0o600); err != nil {
		return err
	}
	p := newProcess(ConfigPath())
	if err := p.Start(); err != nil {
		return err
	}
	sidecarProc, sidecarConf = p, conf
	return nil
}

func stopLocked() {
	if sidecarProc != nil && sidecarProc.IsRunning() {
		_ = sidecarProc.Stop()
	}
	if sidecarProc != nil {
		_ = os.Remove(ConfigPath())
	}
	sidecarProc, sidecarConf = nil, nil
}

// Stop terminates the sidecar if it is running.
func Stop() {
	sidecarMu.Lock()
	defer sidecarMu.Unlock()
	stopLocked()
}
