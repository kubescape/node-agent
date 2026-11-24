//go:build startgate_vmtest

package integration

import (
	"slices"
	"strings"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
)

// TestS5EnableNRIStartGateWiring (startgate_vmtest build): the wiring
// enables the pod gate and creates the plugin once; it refuses a procfs of
// another PID namespace before it changes anything, and a second call.
// Nothing dials: Start is not called.
func TestS5EnableNRIStartGateWiring(t *testing.T) {
	s, _ := nriTestService(t)
	socket := t.TempDir() + "/nri.sock"
	if err := s.enableNRIStartGate(t.Context(), startGateSyscalls(), t.TempDir(), socket); err == nil || s.gate.Load() != nil || s.nriPlugin.Load() != nil || s.gateEnabling.Load() {
		t.Fatalf("another PID namespace: %v (the gate changed)", err)
	}
	if err := s.enableNRIStartGate(t.Context(), startGateSyscalls(), "/proc", socket); err != nil {
		t.Fatal(err)
	}
	if s.gate.Load() == nil || s.nriPlugin.Load() == nil || s.nriGate == nil || s.nriGate.gate != s.gate.Load() {
		t.Fatal("the gate or the plugin is missing")
	}
	if err := s.enableNRIStartGate(t.Context(), startGateSyscalls(), "/proc", socket); err == nil || !strings.Contains(err.Error(), "already enabled") {
		t.Fatalf("second enable = %v", err)
	}
}

// TestS5ReviewF1SynchronizeThroughNRIGate (startgate_vmtest; S5 review v1
// F1, owner ruling batch 6): the plugin over the real nriGate and podGate.
// A dead Selected sandbox (no live pause process, no container), Strict and
// Audit, joins as Unselected and Synchronize completes with it unproven; a
// sandbox with a live pause process, or with a container in Synchronize's
// list, that cannot be marked still fails Synchronize (D10a).
func TestS5ReviewF1SynchronizeThroughNRIGate(t *testing.T) {
	for _, audit := range []bool{false, true} {
		s, backend := nriTestService(t)
		if audit {
			useAuditPolicy(t, s, backend.fakeGateBackend)
		}
		n := readyNRIGate(t, s, backend)
		p, err := startgate.NewPlugin(n, startgate.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Configure(t.Context(), "", "containerd", "v2.3.7"); err != nil {
			t.Fatal(err)
		}
		pods := []*nriapi.PodSandbox{nriTestPod("sb1", 42), nriTestPod("sb-done", 0)}
		if _, err := p.Synchronize(t.Context(), pods, nil); err != nil {
			t.Fatalf("audit=%v: a dead sandbox failed Synchronize: %v", audit, err)
		}
		if !slices.Equal(backend.synced, []string{"0:0"}) || backend.count("MarkPod") != 1 {
			t.Fatalf("audit=%v: synced %v, calls %v", audit, backend.synced, backend.calls)
		}
		n.gate.podMu.Lock()
		joined := len(n.gate.pods["pod-uid"].sandboxes)
		n.gate.podMu.Unlock()
		if joined != 2 {
			t.Fatalf("audit=%v: %d sandboxes joined, want 2", audit, joined)
		}
		// Live but unmarkable: the pause process lives (43) but does not
		// resolve; or it is gone and a container still runs in the sandbox.
		for name, tc := range map[string]struct {
			pod  *nriapi.PodSandbox
			ctrs []*nriapi.Container
		}{
			"live pause":        {nriTestPod("sb-live", 43), nil},
			"running container": {nriTestPod("sb-ctr", 0), []*nriapi.Container{{Id: "c1", PodSandboxId: "sb-ctr", State: nriapi.ContainerState_CONTAINER_RUNNING}}},
		} {
			_, err := p.Synchronize(t.Context(), []*nriapi.PodSandbox{nriTestPod("sb1", 42), tc.pod}, tc.ctrs)
			if err == nil || !strings.Contains(err.Error(), "D10a") {
				t.Fatalf("audit=%v %s: Synchronize = %v", audit, name, err)
			}
		}
		if len(backend.synced) != 1 {
			t.Fatalf("audit=%v: a failed Synchronize synced: %v", audit, backend.synced)
		}
	}
}
