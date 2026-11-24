package startgate

// Tests for the S5 review v1 findings, ported from the reviewer's
// reproductions and turned into regression tests.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func syncPlugin(t *testing.T, g Gate, timeout time.Duration) *Plugin {
	t.Helper()
	p := newPlugin(g, Options{})
	read := func() time.Duration { return timeout }
	p.readTimeout.Store(&read)
	if _, err := p.Configure(t.Context(), "", "containerd", "v2.3.7"); err != nil {
		t.Fatal(err)
	}
	return p
}

// deadSandboxGate: "sb-done" is the NotReady sandbox of a completed Selected
// pod: its pause process is gone, so its pod cgroup does not resolve.
type deadSandboxGate struct {
	classifyByID
}

func (g *deadSandboxGate) Sandbox(pod *api.PodSandbox) (Sandbox, error) {
	sb, err := g.classifyByID.Sandbox(pod)
	if pod.GetId() == "sb-done" {
		sb.CgroupID = 0
		return sb, errors.New("pause process: no PID")
	}
	return sb, err
}

// TestS5ReviewF1DeadSandboxIsUnselected (owner ruling batch 6, F1): a
// sandbox with no live pause process and no container in Synchronize's
// list joins as Unselected, alerts, and does not fail Synchronize, Strict or
// Audit. With a container listed for it, or a live pause process, the same
// unmarkable sandbox still fails Synchronize (D10a).
func TestS5ReviewF1DeadSandboxIsUnselected(t *testing.T) {
	for _, strict := range []bool{false, true} {
		var alerts []Alert
		g := &deadSandboxGate{classifyByID{fakeGate: fakeGate{marks: [][]sandboxpolicy.PodSectionResult{ok()}, dead: map[string]bool{"sb-done": true}},
			byID: map[string]sandboxpolicy.PodClassification{"sb1": sel(true), "sb-done": sel(strict)}}}
		p := syncPlugin(t, g, 2*time.Second)
		p.opts.OnAlert = func(a Alert) { alerts = append(alerts, a) }
		p.epoch.Store(1)
		pods := []*api.PodSandbox{testPod("sb1"), testPod("sb-done")}
		if _, err := p.Synchronize(t.Context(), pods, nil); err != nil {
			t.Fatalf("strict=%v: Synchronize = %v", strict, err)
		}
		if !slices.Equal(g.synced, []string{"1:[]"}) || g.count("JoinUnselected sb-done") != 1 || g.count("JoinAndMark sb-done") != 0 || !hasAlert(alerts, AlertDeadSandbox) {
			t.Fatalf("strict=%v: synced %v, calls %v, alerts %v", strict, g.synced, g.calls, alerts)
		}
		// A container still listed: live, unmarkable, D10a.
		ctrs := []*api.Container{{Id: "c1", PodSandboxId: "sb-done", State: api.ContainerState_CONTAINER_RUNNING}}
		if _, err := p.Synchronize(t.Context(), pods, ctrs); err == nil || !strings.Contains(err.Error(), "D10a") {
			t.Fatalf("strict=%v: a sandbox with a running container passed: %v", strict, err)
		}
		// A live pause process: D10a.
		g.dead = nil
		if _, err := p.Synchronize(t.Context(), pods, nil); err == nil || !strings.Contains(err.Error(), "D10a") {
			t.Fatalf("strict=%v: a live unmarkable sandbox passed: %v", strict, err)
		}
		if len(g.synced) != 1 {
			t.Fatalf("strict=%v: a failed Synchronize synced: %v", strict, g.synced)
		}
	}
	// A dead sandbox whose cgroup the gate knows is never proven, even for
	// an Unselected pod.
	g := &classifyByID{fakeGate: fakeGate{dead: map[string]bool{"sb5": true}}, byID: map[string]sandboxpolicy.PodClassification{"sb5": unselected}}
	p := syncPlugin(t, g, 2*time.Second)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb5")}, nil); err != nil || !slices.Equal(g.synced, []string{"0:[]"}) {
		t.Fatalf("dead Unselected: %v, synced %v", err, g.synced)
	}
}

// TestS5ReviewF5TombstonedSandbox (F5): a sandbox the gate already
// tombstoned does not fail Synchronize for an Unselected pod (and is not
// proven); for a Selected pod it stays fail-closed.
func TestS5ReviewF5TombstonedSandbox(t *testing.T) {
	removed := fmt.Errorf("join: %w", ErrSandboxRemoved)
	g := &classifyByID{fakeGate: fakeGate{joinErr: removed}, byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected}}
	p := syncPlugin(t, g, 2*time.Second)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb1")}, nil); err != nil || !slices.Equal(g.synced, []string{"0:[]"}) || g.count("Unmark") != 0 {
		t.Fatalf("tombstoned Unselected: %v, synced %v, calls %v", err, g.synced, g.calls)
	}
	g = &classifyByID{fakeGate: fakeGate{markErr: removed}, byID: map[string]sandboxpolicy.PodClassification{"sb1": sel(true)}}
	p = syncPlugin(t, g, 2*time.Second)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb1")}, nil); err == nil || len(g.synced) != 0 {
		t.Fatalf("tombstoned Selected: %v, synced %v", err, g.synced)
	}
}

// slowMarkGate's JoinAndMark returns after its delay, ignoring the deadline.
type slowMarkGate struct {
	classifyByID
	delay time.Duration
}

func (g *slowMarkGate) JoinAndMark(ctx context.Context, sb Sandbox, c sandboxpolicy.PodClassification, d time.Time) ([]sandboxpolicy.PodSectionResult, error) {
	time.Sleep(g.delay)
	return g.classifyByID.JoinAndMark(ctx, sb, c, d)
}

// TestS5ReviewF4SynchronizePastDeadlineDoesNotSync (F4, mutation M1): a
// Synchronize whose work ends after its deadline fails and never records
// the epoch as synced.
func TestS5ReviewF4SynchronizePastDeadlineDoesNotSync(t *testing.T) {
	g := &slowMarkGate{classifyByID: classifyByID{fakeGate: fakeGate{marks: [][]sandboxpolicy.PodSectionResult{ok()}}, byID: map[string]sandboxpolicy.PodClassification{"sb1": sel(true)}}, delay: 400 * time.Millisecond}
	p := syncPlugin(t, g, 600*time.Millisecond) // work budget 350 ms
	_, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb1")}, nil)
	if err == nil || !strings.Contains(err.Error(), "work deadline") || len(g.synced) != 0 || p.registered.Load() {
		t.Fatalf("Synchronize = %v, synced %v", err, g.synced)
	}
}

// TestS5ReviewF4StaleUnmarkRetriedOnce (F4, mutation M2): a stale unmark is
// retried once with a fresh classification; a second stale answer fails.
func TestS5ReviewF4StaleUnmarkRetriedOnce(t *testing.T) {
	stale := fmt.Errorf("privilege: %w", sandboxpolicy.ErrStaleSequence)
	for _, handler := range []string{"run", "create"} {
		g := &fakeGate{classes: []sandboxpolicy.PodClassification{unselected}, unmarkErrs: []error{stale, stale, stale}}
		var alerts []Alert
		p := configured(t, g, &alerts)
		var err error
		if handler == "run" {
			err = p.RunPodSandbox(t.Context(), testPod("sb7"))
		} else {
			_, _, err = p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
		}
		if err == nil || g.count("Unmark") != 2 || g.classified != 2 {
			t.Fatalf("%s: err %v, unmarks %d, classified %d", handler, err, g.count("Unmark"), g.classified)
		}
	}
}

// TestS5ReviewF7StatusBounded (F7): a full status evicts its oldest entry
// and counts it, so a new pod is always listed; Synchronize keeps only the
// listed pods; a release drops the pod's entry even when it fails; a mark
// at RunPodSandbox records no Pending.
func TestS5ReviewF7StatusBounded(t *testing.T) {
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{withShape(sel(false), sandboxpolicy.ShapeSources)}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	for i := range statusLimit {
		pod := testPod("x")
		pod.Uid = fmt.Sprintf("stale-%d", i)
		p.setStatus(pod, sel(false), StateFaulted, "stale")
	}
	pod := testPod("sb9")
	pod.Uid = "new-not-start-gated"
	if err := p.RunPodSandbox(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	st := p.Status()
	if len(st) != statusLimit || p.Evicted() != 1 || !slices.ContainsFunc(st, func(s PodStatus) bool { return s.UID == "new-not-start-gated" }) ||
		slices.ContainsFunc(st, func(s PodStatus) bool { return s.UID == "stale-0" }) {
		t.Fatalf("%d entries, evicted %d", len(st), p.Evicted())
	}
	// Synchronize keeps only the pods it lists.
	g.classes = []sandboxpolicy.PodClassification{unselected}
	g.classified = 0
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, nil); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); len(st) != 0 {
		t.Fatalf("after Synchronize: %d entries", len(st))
	}
	// A failed release still drops the entry.
	p.setStatus(pod, sel(true), StateFaulted, "refused")
	g.releaseErr = errors.New("instance not ready")
	if err := p.RemovePodSandbox(t.Context(), pod); err == nil || len(p.Status()) != 0 {
		t.Fatalf("release: %v, status %v", err, p.Status())
	}
	// RunPodSandbox's mark clears an older state instead of recording Pending.
	g.classes = []sandboxpolicy.PodClassification{sel(true)}
	g.marks = [][]sandboxpolicy.PodSectionResult{ok()}
	p.setStatus(pod, sel(true), StatePending, "older")
	if err := p.RunPodSandbox(t.Context(), pod); err != nil || len(p.Status()) != 0 {
		t.Fatalf("run: %v, status %v", err, p.Status())
	}
}

// TestS5ReviewF8BackoffResets (F8): the reconnect pause doubles while
// attempts fail and starts over after a connection that registered.
func TestS5ReviewF8BackoffResets(t *testing.T) {
	var w time.Duration
	var got []time.Duration
	for range 7 {
		w = nextWait(w, false)
		got = append(got, w)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	if !slices.Equal(got, want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
	if nextWait(30*time.Second, true) != reconnectMin {
		t.Fatal("a registered connection did not reset the backoff")
	}
}

// TestS5ReviewF9NoWorkBudget (S5 review v1 F9; lead ruling under D3(a),
// S5 review v2 N2): with no work budget left (WorkDeadline fails), a create
// or start writes no mark and reads nothing back, so Strict, Audit, Unknown
// and exempt are refused (a Selected pod reported Faulted); only a plain
// Unselected container of a pod the gate holds no mark for is admitted.
// The classification reads the caches only: its context is already
// canceled.
func TestS5ReviewF9NoWorkBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		class  sandboxpolicy.PodClassification
		marked bool
		admit  bool
		state  PodState
	}{
		{"audit", sel(false), false, false, StateFaulted},
		{"strict", sel(true), false, false, StateFaulted},
		{"unselected", unselected, false, true, ""},
		{"unselected with a mark", unselected, true, false, ""},
		{"exempt", exempt, false, false, ""},
		{"unknown", unknownCls, false, false, ""},
	} {
		for _, start := range []bool{false, true} {
			g := &ctxGate{fakeGate: fakeGate{classes: []sandboxpolicy.PodClassification{tc.class}, holdsMark: tc.marked}}
			var alerts []Alert
			p := configured(t, g, &alerts)
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(100*time.Millisecond)) // under the margin
			var err error
			if start {
				err = p.StartContainer(ctx, testPod("sb7"), testContainer("app"))
			} else {
				_, _, err = p.CreateContainer(ctx, testPod("sb7"), testContainer("app"))
			}
			cancel()
			noFatal(t, err)
			if (err == nil) != tc.admit || g.count("JoinAndMark") != 0 || g.count("Hold") != 0 || g.count("Unmark") != 0 || !g.canceled {
				t.Fatalf("%s (start %v): err %v, calls %v, canceled %v", tc.name, start, err, g.calls, g.canceled)
			}
			if err != nil && !strings.Contains(err.Error(), "(D3a)") {
				t.Fatalf("%s: %v", tc.name, err)
			}
			st := p.Status()
			if tc.state == "" && len(st) != 0 || tc.state != "" && (len(st) != 1 || st[0].State != tc.state) {
				t.Fatalf("%s: status %v", tc.name, st)
			}
		}
	}
}

// ctxGate records whether Classify got an already-canceled context.
type ctxGate struct {
	fakeGate
	canceled bool
}

func (g *ctxGate) Classify(ctx context.Context, req sandboxpolicy.ClassifyRequest) sandboxpolicy.PodClassification {
	g.canceled = ctx.Err() != nil
	return g.fakeGate.Classify(ctx, req)
}
