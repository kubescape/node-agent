package integration

import (
	"context"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

type capRelease struct {
	*fakeGateBackend
	mu  sync.Mutex
	ids []uint64
}

func (b *capRelease) ReleasePod(ctx context.Context, uid types.UID, c uint64) error {
	b.mu.Lock()
	b.ids = append(b.ids, c)
	b.mu.Unlock()
	return b.fakeGateBackend.ReleasePod(ctx, uid, c)
}

// S3 review v3 R1 (the reviewer's repro): JoinUnselected of an unresolved (cgroup 0) sandbox on a
// fresh entry overwrites p.sandbox, so the pod's known cgroup is lost and the
// last removal releases cgroup 0.
func TestV3ReviewUnselectedZeroOverwritesKnownCgroup(t *testing.T) {
	b := &capRelease{fakeGateBackend: newFakeGateBackend()}
	g := newPodGate(t.Context(), b, func(uint64) bool { return true })
	s1 := testSandbox("S1")
	if err := g.JoinUnselected(s1); err != nil {
		t.Fatal(err)
	}
	s2 := testSandbox("S2")
	s2.CgroupID, s2.CgroupPath = 0, ""
	if err := g.JoinUnselected(s2); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseSandbox(t.Context(), s1, soon()); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseSandbox(t.Context(), s2, soon()); err != nil {
		t.Fatal(err)
	}
	g.wait()
	t.Logf("s1 cgroup %d; released %v", s1.CgroupID, b.ids)
	g.prune()
	g.podMu.Lock()
	_, kept := g.pods[s1.UID]
	g.podMu.Unlock()
	if len(b.ids) != 1 || b.ids[0] != s1.CgroupID || kept {
		t.Fatalf("released %v (want [%d]); entry kept after prune with every cgroup gone: %v", b.ids, s1.CgroupID, kept)
	}
}
