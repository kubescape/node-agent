//go:build startgate_vmtest

package startgate

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// TestS5VMTestBuildRegistrationGate: under startgate_vmtest the plugin is
// buildable. Run dials only while the registration gate holds; each
// connection attempt is a new epoch, and its end is recorded
// (SetNRIDisconnected) whether or not the stub saw it close. The dialer is a
// fake: no socket is opened.
func TestS5VMTestBuildRegistrationGate(t *testing.T) {
	if !Buildable() {
		t.Fatal("the startgate_vmtest build reports the start gate not buildable")
	}
	if buildMarker != "kubescape-startgate-buildable=true" {
		t.Fatalf("marker %q in the startgate_vmtest build", buildMarker)
	}
	g := &fakeGate{registerErr: errors.New("informers not synced")}
	var dials atomic.Int32
	p, err := NewPlugin(g, Options{SocketPath: t.TempDir() + "/nri.sock"})
	if err != nil {
		t.Fatal(err)
	}
	p.opts.dial = func(string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no socket in a unit test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 0 || g.count("Registration") == 0 || len(g.disconnects) != 0 || p.epoch.Load() != 0 {
		t.Fatalf("closed gate: dials %d, calls %v, disconnects %v, epoch %d", dials.Load(), g.calls, g.disconnects, p.epoch.Load())
	}
	g.registerErr = nil
	ctx, cancel = context.WithTimeout(t.Context(), 2500*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	n := dials.Load()
	if n < 2 {
		t.Fatalf("open gate: %d dials, want at least 2 (a retry)", n)
	}
	want := make([]uint64, 0, n)
	for e := uint64(1); e <= uint64(n); e++ {
		want = append(want, e)
	}
	if !slices.Equal(g.disconnects, want) {
		t.Fatalf("disconnects %v, want one per epoch %v", g.disconnects, want)
	}
}
