package singbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

var (
	gracefulStopTimeout = 5 * time.Second
	forceStopTimeout    = 2 * time.Second
)

type logWriter struct {
	mu  sync.Mutex
	buf string
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf += string(p)
	for {
		i := strings.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *logWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != "" {
		w.emit(w.buf)
		w.buf = ""
	}
}

func (w *logWriter) emit(line string) {
	if trimmed := strings.TrimSpace(line); trimmed != "" {
		logger.Infof("singbox: %s", trimmed)
	}
}

type process struct {
	mu              sync.RWMutex
	cmd             *exec.Cmd
	done            chan struct{}
	configPath      string
	logs            *logWriter
	intentionalStop atomic.Bool
}

func newProcess(configPath string) *process {
	return &process{configPath: configPath, logs: &logWriter{}}
}

func (p *process) IsRunning() bool {
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if done != nil {
		select {
		case <-done:
			return false
		default:
		}
	}
	return true
}

func (p *process) Start() error {
	if p.IsRunning() {
		return errors.New("sing-box is already running")
	}
	cmd := exec.CommandContext(context.Background(), GetBinaryPath(), "run", "-c", p.configPath)
	cmd.Stdout = p.logs
	cmd.Stderr = p.logs
	done := make(chan struct{})
	p.mu.Lock()
	p.cmd, p.done = cmd, done
	p.mu.Unlock()
	p.intentionalStop.Store(false)
	if err := cmd.Start(); err != nil {
		close(done)
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()
		return err
	}
	attachChildLifetime(cmd)
	go p.wait(cmd, done)
	return nil
}

func (p *process) wait(cmd *exec.Cmd, done chan struct{}) {
	defer close(done)
	err := cmd.Wait()
	p.logs.Flush()
	if err != nil && !p.intentionalStop.Load() {
		logger.Errorf("singbox: sing-box process exited: %v", err)
	}
}

func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("sing-box is not running")
	}
	p.intentionalStop.Store(true)
	p.mu.RLock()
	cmd, done := p.cmd, p.done
	p.mu.RUnlock()

	if runtime.GOOS == "windows" {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return waitForExit(done, forceStopTimeout)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return waitForExit(done, forceStopTimeout)
		}
		return err
	}
	if err := waitForExit(done, gracefulStopTimeout); err == nil {
		return nil
	}
	logger.Warning("singbox: sing-box did not stop after SIGTERM, killing process")
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return waitForExit(done, forceStopTimeout)
}

func waitForExit(done <-chan struct{}, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("timed out waiting for sing-box to stop after %s", timeout)
	}
}
