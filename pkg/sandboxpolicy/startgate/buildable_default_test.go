//go:build !startgate_vmtest

package startgate

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

// TestS5DefaultBuildNeverDials: in the default build the enablement
// constant is false: Buildable reports it, NewPlugin returns ErrNotBuildable
// before it touches the gate, and Run refuses without a registration check
// or a dial. No option reaches the dialer (it is unexported).
func TestS5DefaultBuildNeverDials(t *testing.T) {
	if Buildable() {
		t.Fatal("the default build reports the start gate buildable")
	}
	g := &fakeGate{}
	var dials atomic.Int32
	p, err := NewPlugin(g, Options{SocketPath: t.TempDir() + "/nri.sock"})
	if !errors.Is(err, ErrNotBuildable) || p != nil {
		t.Fatalf("NewPlugin = %v, %v; want ErrNotBuildable", p, err)
	}
	// Even a plugin built behind NewPlugin's back never runs in this build.
	q := newPlugin(g, Options{dial: func(string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no socket in a unit test")
	}})
	if err := q.Run(t.Context()); !errors.Is(err, ErrNotBuildable) {
		t.Fatalf("Run = %v, want ErrNotBuildable", err)
	}
	if dials.Load() != 0 || len(g.calls) != 0 || len(g.disconnects) != 0 {
		t.Fatalf("dials %d, gate calls %v, disconnects %v", dials.Load(), g.calls, g.disconnects)
	}
}

// TestS5ReviewV2N3BuildMarker (S5 review v2 N3): the binary-level marker
// follows the constant (the release gate greps release binaries for it),
// and its init keeps it reachable.
func TestS5ReviewV2N3BuildMarker(t *testing.T) {
	if buildMarker != "kubescape-startgate-buildable=false" || buildMarkerSink.Load() == nil || *buildMarkerSink.Load() != buildMarker {
		t.Fatalf("marker %q", buildMarker)
	}
}
