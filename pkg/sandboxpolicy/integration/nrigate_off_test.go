//go:build !startgate_vmtest

package integration

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
)

// sockets counts this process's socket descriptors.
func sockets(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, fd := range fds {
		if link, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && strings.HasPrefix(link, "socket:") {
			n++
		}
	}
	return n
}

// TestS5GateOffEnableChangesNothing: with the build constant false,
// EnableNRIStartGate returns ErrNotBuildable and changes nothing: no pod
// gate, no plugin, the gate not marked enabling (enableStartGate never ran),
// no new goroutine and no new socket. cmd/main.go does not even call it
// (startgate.Buildable() is false), and Start finds no plugin to run.
func TestS5GateOffEnableChangesNothing(t *testing.T) {
	s, backend := nriTestService(t)
	runtime.GC()
	goroutines, socks := runtime.NumGoroutine(), sockets(t)
	if err := s.EnableNRIStartGate(t.Context()); !errors.Is(err, startgate.ErrNotBuildable) {
		t.Fatalf("EnableNRIStartGate = %v, want ErrNotBuildable", err)
	}
	if s.gate.Load() != nil || s.nriPlugin.Load() != nil || s.nriGate != nil || s.gateEnabling.Load() {
		t.Fatal("the gate-off build enabled something")
	}
	if backend.gate != nil || len(backend.calls) != 0 {
		t.Fatalf("the backend was touched: start gate %v, calls %v", backend.gate, backend.calls)
	}
	time.Sleep(50 * time.Millisecond)
	if g, k := runtime.NumGoroutine(), sockets(t); g > goroutines || k != socks {
		t.Fatalf("goroutines %d -> %d, sockets %d -> %d", goroutines, g, socks, k)
	}
	if s.startGateStatus() != nil {
		t.Fatal("the gate-off status lists pods")
	}
}
