//go:build startgate_vmtest

package startgate

// Wire tests (S5 review v1 F3): the plugin against containerd/nri's own
// in-process runtime side (pkg/adaptation) over a unix socket in a temp
// directory. No containerd, no root, no VM. The runtime runs in this
// process; the plugin dials it through Run, as in production.

import (
	"context"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	nri "github.com/containerd/nri/pkg/adaptation"
	validator "github.com/containerd/nri/plugins/default-validator/builtin"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// slowHoldGate's hold sleeps past the runtime's request timeout while slow
// is set: a handler overrun (what the work deadline exists to prevent).
type slowHoldGate struct {
	fakeGate
	slow atomic.Bool
}

func (g *slowHoldGate) HoldUntilConfirmed(ctx context.Context, sb Sandbox, c sandboxpolicy.PodClassification, d time.Time) ([]sandboxpolicy.PodSectionConfirmation, error) {
	if g.slow.Load() {
		time.Sleep(1500 * time.Millisecond)
	}
	return g.fakeGate.HoldUntilConfirmed(ctx, sb, c, d)
}

func (g *slowHoldGate) syncedN() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.synced)
}

func (g *slowHoldGate) disconnectsNow() []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.disconnects)
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wireRuntime starts an in-process NRI runtime on a temp socket, with the
// default validator requiring this plugin when required is set.
func wireRuntime(t *testing.T, required bool) (*nri.Adaptation, string) {
	t.Helper()
	nri.SetPluginRequestTimeout(1200 * time.Millisecond)
	dir := t.TempDir()
	sock := filepath.Join(dir, "nri.sock")
	pods := []*nri.PodSandbox{testPod("sb1")}
	opts := []nri.Option{nri.WithSocketPath(sock), nri.WithPluginPath(filepath.Join(dir, "plugins")), nri.WithPluginConfigPath(filepath.Join(dir, "conf"))}
	if required {
		opts = append(opts, nri.WithDefaultValidator(&validator.DefaultValidatorConfig{Enable: true, RequiredPlugins: []string{PluginIndex + "-" + PluginName}}))
	}
	r, err := nri.New("containerd", "v2.3.7",
		func(ctx context.Context, cb nri.SyncCB) error { _, err := cb(ctx, pods, nil); return err },
		func(context.Context, []*nri.ContainerUpdate) ([]*nri.ContainerUpdate, error) { return nil, nil },
		opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Stop)
	return r, sock
}

// TestS5WireRegistrationRefusalOverrunReconnect: over the wire,
//  1. the plugin registers: Configure reads the runtime's request timeout
//     and Synchronize records epoch 1;
//  2. a Strict refusal arrives as an ordinary (non-fatal) error and the
//     plugin stays registered (a second create is refused on epoch 1, with
//     no disconnect);
//  3. a handler that overruns the request timeout is fatal at the runtime:
//     the create is ADMITTED and the plugin closed (epoch 1 disconnected).
//     This is the known residual. required_plugins does NOT cover this
//     create itself; it covers the creates that follow while the plugin is
//     gone (TestS5WireRequiredPluginsAfterOverrun);
//  4. the plugin reconnects within reconnectMin (the backoff reset after a
//     registered connection) and syncs epoch 2; creates are refused again.
func TestS5WireRegistrationRefusalOverrunReconnect(t *testing.T) {
	r, sock := wireRuntime(t, false)
	g := &slowHoldGate{fakeGate: fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{ok()},
		confs: conf(sandboxpolicy.PodSectionFaulted, true)}}
	p, err := NewPlugin(g, Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = p.Run(ctx) }()
	waitFor(t, "registration", 5*time.Second, func() bool { return g.syncedN() == 1 })
	if got := time.Duration(p.requestTimeout.Load()); got != 1200*time.Millisecond {
		t.Fatalf("request timeout %v, want the runtime's 1.2s", got)
	}
	req := &nri.CreateContainerRequest{Pod: testPod("sb1"), Container: testContainer("app")}
	for i := range 2 {
		if _, err := r.CreateContainer(t.Context(), req); err == nil {
			t.Fatalf("create %d: a Strict Faulted create was admitted over the wire", i)
		} else {
			t.Logf("create %d refused (non-fatal): %v", i, err)
		}
	}
	if d := g.disconnectsNow(); len(d) != 0 || p.epoch.Load() != 1 {
		t.Fatalf("a refusal closed the plugin: disconnects %v, epoch %d", d, p.epoch.Load())
	}
	g.slow.Store(true)
	_, err = r.CreateContainer(t.Context(), req)
	t.Logf("overrun: CreateContainer err = %v (nil: admitted, the known residual)", err)
	if err != nil {
		t.Fatalf("the overrun was not the documented admitted-and-closed residual: %v", err)
	}
	waitFor(t, "the close of epoch 1", 3*time.Second, func() bool { return slices.Contains(g.disconnectsNow(), 1) })
	g.slow.Store(false)
	closed := time.Now()
	waitFor(t, "reconnect and sync of epoch 2", 5*time.Second, func() bool { return g.syncedN() == 2 })
	if took := time.Since(closed); took > reconnectMin+time.Second {
		t.Fatalf("reconnect took %v: the backoff did not reset", took)
	}
	if g.synced[1] != "2:[]" && g.synced[1] != "2:[1]" {
		t.Fatalf("second sync %q, want epoch 2", g.synced[1])
	}
	if _, err := r.CreateContainer(t.Context(), req); err == nil {
		t.Fatal("after the reconnect a Strict Faulted create was admitted")
	}
}

// TestS5WireRequiredPluginsAfterOverrun: with the runtime's default
// validator requiring 10-kubescape-start-gate (containerd's
// required_plugins):
//   - a create before the plugin registered is refused;
//   - a Confirmed create is admitted;
//   - the create whose handler overruns is still ADMITTED: the plugin took
//     part in the request, so the validator finds it (measured here; the
//     residual required_plugins does not cover);
//   - the creates that follow while the plugin is closed are refused.
func TestS5WireRequiredPluginsAfterOverrun(t *testing.T) {
	r, sock := wireRuntime(t, true)
	g := &slowHoldGate{fakeGate: fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{ok()},
		confs: conf(sandboxpolicy.PodSectionConfirmed, true)}}
	p, err := NewPlugin(g, Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	req := &nri.CreateContainerRequest{Pod: testPod("sb1"), Container: testContainer("app")}
	if _, err := r.CreateContainer(t.Context(), req); err == nil {
		t.Fatal("a create with the required plugin absent was admitted")
	} else {
		t.Logf("plugin absent: refused: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = p.Run(ctx) }()
	waitFor(t, "registration", 5*time.Second, func() bool { return g.syncedN() == 1 })
	if _, err := r.CreateContainer(t.Context(), req); err != nil {
		t.Fatalf("a Confirmed create was refused with the plugin registered: %v", err)
	}
	g.slow.Store(true)
	_, err = r.CreateContainer(t.Context(), req)
	t.Logf("overrun with required_plugins: CreateContainer err = %v (nil: admitted)", err)
	if err != nil {
		t.Fatalf("the overrun create's outcome changed (it was admitted when measured): %v", err)
	}
	waitFor(t, "the close of epoch 1", 3*time.Second, func() bool { return slices.Contains(g.disconnectsNow(), 1) })
	// Before the reconnect (reconnectMin): the plugin is absent.
	if _, err := r.CreateContainer(t.Context(), req); err == nil {
		t.Fatal("with required_plugins, a create while the plugin is closed was admitted")
	} else {
		t.Logf("plugin closed: refused: %v", err)
	}
}
