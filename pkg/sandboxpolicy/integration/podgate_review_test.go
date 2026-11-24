package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

// blockingRelease: ReleasePod does its delete, then waits before returning,
// so the release job is still the worker's current job.
type blockingRelease struct {
	*fakeGateBackend
	entered chan struct{}
	hold    chan struct{}
}

func (b *blockingRelease) ReleasePod(ctx context.Context, uid types.UID, c uint64) error {
	err := b.fakeGateBackend.ReleasePod(ctx, uid, c)
	b.entered <- struct{}{}
	<-b.hold
	return err
}

// S3 review v1 #2 (repro R1): afterBind's re-release is deduplicated into the running release job.
func TestReviewReleaseDedupedAgainstCurrent(t *testing.T) {
	inner := newFakeGateBackend()
	b := &blockingRelease{fakeGateBackend: inner, entered: make(chan struct{}, 1), hold: make(chan struct{})}
	g := newPodGate(t.Context(), b, nil)
	seq := sandboxpolicy.Seq{Config: 1, Input: 1}
	c := selected(seq, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); err != nil {
		t.Fatal(err)
	}
	// A refresh merges before the release.
	sent, before := g.merge(nil, seq, nil)
	if len(sent) != 1 {
		t.Fatalf("merge: %+v", sent)
	}
	relDone := make(chan error, 1)
	go func() { relDone <- g.ReleaseSandbox(context.Background(), testSandbox("A"), soon()) }()
	<-b.entered // ReleasePod deleted the record; job still current
	if err := b.BindPodsAt(t.Context(), sent, seq); err != nil {
		t.Fatal(err)
	}
	g.afterBind(sent, before) // should queue a second ReleasePod
	close(b.hold)
	if err := <-relDone; err != nil {
		t.Fatal(err)
	}
	g.wait()
	// drain any second release
	for len(b.entered) > 0 {
		<-b.entered
	}
	if r := inner.rec("pod-uid"); r != nil {
		t.Fatalf("released pod is bound again after afterBind (re-release deduped into the running job); ReleasePod calls=%d", inner.count("ReleasePod"))
	}
}

// S3 review v1 #1 (repro R2): a RemovePodSandbox of an old, never-joined sandbox marks a live pod
// released; the API path then never binds it.
func TestReviewNeverJoinedReleaseExcludesAPIPod(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	old := testSandbox("old-sandbox")
	if err := g.ReleaseSandbox(t.Context(), old, soon()); err != nil {
		t.Fatal(err)
	}
	api := []sandboxpolicy.PodBinding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", CgroupID: 77, Plan: sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p1", "enforce")}}}}
	out, _ := g.merge(api, sandboxpolicy.Seq{Config: 9, Input: 9}, nil)
	if len(out) == 0 {
		t.Fatalf("live pod %q (cgroup 77) is dropped from the API bind list after an old sandbox's removal", "pod-uid")
	}
}

// S3 review v1 #3 (repro R3): enableStartGate accepts a checker that can never decide (EPERM).
func TestReviewEnableWithoutCapability(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	sys := startGateSyscalls()
	sys.openByHandle = func(int, unix.FileHandle, int) (int, error) { return -1, unix.EPERM }
	if err := s.enableStartGate(t.Context(), sys); err == nil {
		t.Fatalf("gate enabled with a gone proof that always answers EPERM")
	}
	if s.gate.Load() != nil || len(b.callNames()) != 0 {
		t.Fatalf("a failed self-test changed something: gate %v, backend calls %v", s.gate.Load() != nil, b.callNames())
	}
	// Without the capability itself, too.
	sys = startGateSyscalls()
	sys.dacReadSearch = func() (bool, error) { return false, nil }
	if err := s.enableStartGate(t.Context(), sys); err == nil || s.gate.Load() != nil || len(b.callNames()) != 0 {
		t.Fatalf("gate enabled without CAP_DAC_READ_SEARCH: %v", err)
	}
	// A failed enable can be retried; a second enable is refused.
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err == nil {
		t.Fatal("a second enableStartGate succeeded")
	}
	if got := b.callNames(); len(got) != 2 {
		t.Fatalf("calls after one enable and one refused enable: %v", got)
	}
}

// S3 review v1 #1 (repro R2b): a running pod bound by the API path (policy added later) loses its
// binding when an old sandbox of it is garbage-collected, and stays unbound.
func TestReviewOldSandboxGCUnbindsAPIPod(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	plan := sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p1", "enforce")}}
	apiPods := []sandboxpolicy.PodBinding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", CgroupID: 77, Plan: plan}}
	seq := sandboxpolicy.Seq{Config: 5, Input: 5}
	out, rel := g.merge(apiPods, seq, nil)
	_ = b.BindPodsAt(t.Context(), out, seq)
	g.afterBind(out, rel)
	if b.rec("pod-uid") == nil {
		t.Fatal("setup: API bind")
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("old-exited-sandbox"), soon()); err != nil {
		t.Fatal(err)
	}
	seq2 := sandboxpolicy.Seq{Config: 6, Input: 6}
	out, rel = g.merge(apiPods, seq2, nil)
	_ = b.BindPodsAt(t.Context(), out, seq2)
	g.afterBind(out, rel)
	g.wait()
	if b.rec("pod-uid") == nil {
		t.Fatalf("live Strict pod unbound by an old sandbox's RemovePodSandbox and never rebound (sent %d pods)", len(out))
	}
}

// A release whose ReleasePod is held: a new sandbox's mark queues behind it,
// and lands after it (the pod is marked again, by the new sandbox).
func TestPodGateReleaseHeldInReleasePod(t *testing.T) {
	inner := newFakeGateBackend()
	b := &blockingRelease{fakeGateBackend: inner, entered: make(chan struct{}, 2), hold: make(chan struct{})}
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); err != nil {
		t.Fatal(err)
	}
	short := func() time.Time { return time.Now().Add(20 * time.Millisecond) }
	if err := g.ReleaseSandbox(t.Context(), testSandbox("A"), short()); !errors.Is(err, errWorkDeadline) {
		t.Fatalf("held release: %v", err)
	}
	<-b.entered
	// A retried removal of the same sandbox while the release runs waits
	// for it (S3 review v2 N4), here until its own deadline.
	if err := g.ReleaseSandbox(t.Context(), testSandbox("A"), short()); !errors.Is(err, errWorkDeadline) {
		t.Fatalf("retried removal during the held release: %v", err)
	}
	c2 := selected(sandboxpolicy.Seq{Config: 2, Input: 2}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("B"), c2, short()); !errors.Is(err, errWorkDeadline) {
		t.Fatalf("mark queued behind the held release: %v", err)
	}
	close(b.hold)
	g.wait()
	if got := inner.callNames(); !slices.Equal(got, []string{"MarkPod", "ReleasePod", "MarkPod"}) {
		t.Fatalf("calls: %v", got)
	}
	if r := inner.rec("pod-uid"); r == nil || r.seq != c2.Seq {
		t.Fatalf("the new sandbox's mark: %+v", r)
	}
}

// JoinUnselected records a sandbox without a backend write, and "last
// sandbox" counts it.
func TestPodGateJoinUnselected(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); err != nil {
		t.Fatal(err)
	}
	if err := g.JoinUnselected(testSandbox("B")); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("A"), soon()); err != nil {
		t.Fatal(err)
	}
	if b.count("ReleasePod") != 0 {
		t.Fatal("an Unselected joined sandbox was not counted: the pod was released")
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("B"), soon()); err != nil {
		t.Fatal(err)
	}
	if b.count("ReleasePod") != 1 {
		t.Fatalf("the last joined sandbox must release the pod: %v", b.callNames())
	}
	// An Unselected-only pod: no plan, never merged, no backend write.
	other := gateSandbox{UID: "u2", Namespace: "ns", Name: "p2", SandboxID: "C", CgroupID: 80}
	if err := g.JoinUnselected(other); err != nil {
		t.Fatal(err)
	}
	if out, _ := g.merge(nil, sandboxpolicy.Seq{}, nil); len(out) != 0 {
		t.Fatalf("an Unselected join was merged: %+v", out)
	}
	if err := g.JoinUnselected(testSandbox("A")); !errors.Is(err, errSandboxRemoved) {
		t.Fatalf("a tombstoned sandbox joined: %v", err)
	}
	g.wait()
	if got := b.callNames(); !slices.Equal(got, []string{"MarkPod", "ReleasePod"}) {
		t.Fatalf("calls: %v", got)
	}
}

// LOW 11: no cgroup, no join; cgroups are kept per sandbox.
func TestPodGateCgroupPerSandbox(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 5, Input: 5}, gatePolicy("p1", api.ModeEnforce))
	zero := testSandbox("Z")
	zero.CgroupID = 0
	if _, err := g.JoinAndMark(t.Context(), zero, c, soon()); !errors.Is(err, errNoCgroup) {
		t.Fatalf("cgroup 0 mark: %v", err)
	}
	// An unresolved cgroup still joins (S3 review v2 N1): it counts.
	if err := g.JoinUnselected(zero); err != nil {
		t.Fatalf("cgroup 0 join: %v", err)
	}
	g.podMu.Lock()
	_, counted := g.pods["pod-uid"].sandboxes["Z"]
	g.podMu.Unlock()
	if !counted {
		t.Fatal("a sandbox with an unresolved cgroup was not counted")
	}
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); err != nil {
		t.Fatal(err)
	}
	// An older classification for another sandbox on another cgroup: the
	// entry keeps the newer one's cgroup, and tracks both.
	sb := testSandbox("B")
	sb.CgroupID = 99
	if _, err := g.JoinAndMark(t.Context(), sb, selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
		t.Fatal(err)
	}
	g.podMu.Lock()
	e := g.pods["pod-uid"]
	cg := e.cgroups()
	g.podMu.Unlock()
	if e.sandbox.CgroupID != 77 || len(cg) != 2 || !slices.Contains(cg, 99) {
		t.Fatalf("cgroups %v, entry cgroup %d", cg, e.sandbox.CgroupID)
	}
	// Only when every tracked cgroup is gone does prune drop the entry.
	gone := map[uint64]bool{77: true}
	g.gone = func(id uint64) bool { return gone[id] }
	g.prune()
	g.podMu.Lock()
	kept := g.pods["pod-uid"] != nil
	g.podMu.Unlock()
	if !kept {
		t.Fatal("prune dropped an entry with a live cgroup")
	}
	gone[99] = true
	g.prune()
	g.podMu.Lock()
	kept = g.pods["pod-uid"] != nil
	g.podMu.Unlock()
	if kept {
		t.Fatal("prune kept an entry whose cgroups are all gone")
	}
	g.wait()
}

// LOW 6: Unmark changes the entry only when the backend accepts it.
func TestPodGateUnmarkRefusedKeepsPlan(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 5, Input: 5}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); err != nil {
		t.Fatal(err)
	}
	// The backend holds a newer write: the unmark is refused.
	b.mu.Lock()
	b.records["pod-uid"].seq = sandboxpolicy.Seq{Config: 9, Input: 9}
	b.mu.Unlock()
	if err := g.Unmark(t.Context(), testSandbox("A"), sandboxpolicy.Seq{Config: 6, Input: 6}, soon()); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("refused unmark: %v", err)
	}
	g.podMu.Lock()
	e := *g.pods["pod-uid"]
	g.podMu.Unlock()
	if e.seq != c.Seq || len(e.plan.Policies) != 1 {
		t.Fatalf("a refused unmark changed the entry: %+v", e)
	}
	g.wait()
}

// LOW 10: a stale refusal joined with a context error keeps its identity.
func TestReplyErrorKeepsStale(t *testing.T) {
	err := replyError(errors.Join(fmt.Errorf("pod: %w", sandboxpolicy.ErrStaleSequence), context.Canceled))
	if !errors.Is(err, sandboxpolicy.ErrStaleSequence) || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("replyError: %v", err)
	}
	if err := replyError(fmt.Errorf("x: %w", context.DeadlineExceeded)); errors.Is(err, context.DeadlineExceeded) || errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("replyError: %v", err)
	}
}

// #5: Close stops the gate's workers before the backend closes; with the
// gate off, Close is main's (TestServiceStartGateOffMatchesHEADGolden).
func TestServiceCloseStopsGateBeforeBackend(t *testing.T) {
	s, _ := testService(t)
	b := newFakeGateBackend()
	s.backend = b
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	g := s.gate.Load()
	b.markGate, b.markEntered = make(chan struct{}), make(chan struct{}, 1)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, time.Now().Add(20*time.Millisecond)); !errors.Is(err, errWorkDeadline) {
		t.Fatal(err)
	}
	<-b.markEntered
	var workersDone bool
	b.onClose = func() {
		// A worker removes itself, under podMu, after its last job.
		g.podMu.Lock()
		workersDone = len(g.workers) == 0
		g.podMu.Unlock()
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(b.markGate)
	}()
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !workersDone {
		t.Fatal("the backend closed while a gate worker was still writing")
	}
	if g.ctx.Err() == nil {
		t.Fatal("close did not cancel the workers' context")
	}
	if _, err := g.JoinAndMark(t.Context(), testSandbox("A"), c, soon()); !errors.Is(err, errGateClosed) {
		t.Fatalf("work after close: %v", err)
	}
}

// S3 review v2 N1 (repro V2-A): the newest sandbox's cgroup is not resolved
// yet; the kubelet then garbage-collects the old joined sandbox. The live
// pod must not be released, nor left out of the API bind list.
func TestV2ReviewUnjoinableNewestSandboxReleasesLivePod(t *testing.T) {
	for _, selectedJoin := range []bool{false, true} {
		t.Run(fmt.Sprintf("selected=%v", selectedJoin), func(t *testing.T) {
			b := newFakeGateBackend()
			g := newPodGate(t.Context(), b, nil)
			seq := sandboxpolicy.Seq{Config: 1, Input: 1}
			if _, err := g.JoinAndMark(t.Context(), testSandbox("S1"), selected(seq, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
				t.Fatal(err)
			}
			s2 := testSandbox("S2")
			s2.CgroupID = 0
			if selectedJoin {
				if _, err := g.JoinAndMark(t.Context(), s2, selected(seq, gatePolicy("p1", api.ModeEnforce)), soon()); !errors.Is(err, errNoCgroup) {
					t.Fatalf("mark without a cgroup: %v", err)
				}
			} else if err := g.JoinUnselected(s2); err != nil {
				t.Fatalf("an unresolved sandbox must still join: %v", err)
			}
			if err := g.ReleaseSandbox(t.Context(), testSandbox("S1"), soon()); err != nil {
				t.Fatal(err)
			}
			plan := sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p2", api.ModeEnforce)}}
			apiPods := []sandboxpolicy.PodBinding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", CgroupID: 77, Plan: plan}}
			out, _ := g.merge(apiPods, sandboxpolicy.Seq{Config: 9, Input: 9}, nil)
			if len(out) == 0 || b.count("ReleasePod") != 0 {
				t.Fatalf("live pod (sandbox S2 running) released or left out of the API bind list: sent %d, releases %d", len(out), b.count("ReleasePod"))
			}
			// S2's removal is the last: it releases the pod's known cgroup.
			if err := g.ReleaseSandbox(t.Context(), s2, soon()); err != nil {
				t.Fatal(err)
			}
			g.wait()
			if b.count("ReleasePod") != 1 {
				t.Fatalf("the last sandbox did not release the pod: %v", b.callNames())
			}
		})
	}
}

// S3 review v2 N4 (repro V2-B): a runtime retry of RemovePodSandbox waits
// for the release the first call queued, bounded by its deadline.
type heldRelease struct {
	*fakeGateBackend
	hold chan struct{}
}

func (b *heldRelease) ReleasePod(ctx context.Context, uid types.UID, c uint64) error {
	<-b.hold
	return b.fakeGateBackend.ReleasePod(ctx, uid, c)
}

func TestV2ReviewRetriedRemoveReportsDoneEarly(t *testing.T) {
	inner := newFakeGateBackend()
	b := &heldRelease{fakeGateBackend: inner, hold: make(chan struct{})}
	g := newPodGate(t.Context(), b, nil)
	seq := sandboxpolicy.Seq{Config: 1, Input: 1}
	if _, err := g.JoinAndMark(t.Context(), testSandbox("S1"), selected(seq, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := g.ReleaseSandbox(ctx, testSandbox("S1"), soon()); !errors.Is(err, errHandlerGone) {
		t.Fatalf("first: %v", err)
	}
	err := g.ReleaseSandbox(t.Context(), testSandbox("S1"), time.Now().Add(30*time.Millisecond))
	if !errors.Is(err, errWorkDeadline) || inner.rec("pod-uid") == nil {
		t.Fatalf("a retried removal reported %v while ReleasePod had not run", err)
	}
	// Once the release runs, a retry waiting for it gets its result.
	retried := make(chan error, 1)
	go func() { retried <- g.ReleaseSandbox(t.Context(), testSandbox("S1"), soon()) }()
	close(b.hold)
	if err := <-retried; err != nil {
		t.Fatal(err)
	}
	g.wait()
	if inner.rec("pod-uid") != nil {
		t.Fatal("the release did not run")
	}
	// After it finished, a retry returns at once.
	if err := g.ReleaseSandbox(t.Context(), testSandbox("S1"), soon()); err != nil {
		t.Fatal(err)
	}
}

// S3 review v2 N3 (repro V2-C): a kernel or LSM that never answers ESTALE
// fails the self-test's negative probe: the gate stays off.
func TestV2ReviewSelfTestDoesNotProveGone(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	sys := startGateSyscalls()
	sys.openByHandle = func(_ int, h unix.FileHandle, _ int) (int, error) {
		if handleID(h) == 1 {
			return 101, nil
		}
		return -1, unix.ENOENT // never ESTALE
	}
	if err := s.enableStartGate(t.Context(), sys); err == nil || s.gate.Load() != nil || len(b.callNames()) != 0 {
		t.Fatalf("gate enabled although no ID can ever answer ESTALE: %v", err)
	}
}

// S3 review v2 N6: enableStartGate refuses once the refresh loop started.
func TestV2ReviewEnableAfterStartRefused(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	s.mu.Lock()
	s.cancel = func() {}
	s.mu.Unlock()
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err == nil || s.gate.Load() != nil || len(b.callNames()) != 0 {
		t.Fatalf("gate enabled after Start: %v", err)
	}
	s.mu.Lock()
	s.cancel = nil
	s.mu.Unlock()
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatalf("a refused enable must leave the guard free: %v", err)
	}
}
