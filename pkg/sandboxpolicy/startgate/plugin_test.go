package startgate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// fakeGate is the Gate of the handler tests: each answer is scripted, every
// call recorded.
type fakeGate struct {
	mu      sync.Mutex
	calls   []string
	classes []sandboxpolicy.PodClassification // Classify answers in order; the last repeats
	// byContainer, when set, answers Classify by the request's container
	// ("" is the pod-level classification).
	byContainer map[string]sandboxpolicy.PodClassification
	classified  int
	sandboxErr  error
	marks       [][]sandboxpolicy.PodSectionResult // JoinAndMark answers in order; the last repeats
	markErr     error
	confs       []sandboxpolicy.PodSectionConfirmation
	holdErr     error
	unmarkErrs  []error
	joinErr     error
	releaseErr  error
	registerErr error
	// dead names the sandboxes whose pause process is gone.
	dead        map[string]bool
	holdsMark   bool
	synced      []string
	disconnects []uint64
}

func (g *fakeGate) record(format string, args ...any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, fmt.Sprintf(format, args...))
}

func (g *fakeGate) count(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, c := range g.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (g *fakeGate) Classify(_ context.Context, req sandboxpolicy.ClassifyRequest) sandboxpolicy.PodClassification {
	g.record("Classify %s %v", req.Container, req.ContainerInPodCgroup)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byContainer != nil {
		return g.byContainer[req.Container]
	}
	c := g.classes[min(g.classified, len(g.classes)-1)]
	g.classified++
	if req.ContainerInPodCgroup && c.Class == sandboxpolicy.PodSelected {
		c.Shape |= sandboxpolicy.ShapeContainerInPodCgroup
	}
	return c
}

func (g *fakeGate) Sandbox(pod *api.PodSandbox) (Sandbox, error) {
	sb := Sandbox{UID: types.UID(pod.GetUid()), Namespace: pod.GetNamespace(), Name: pod.GetName(), ID: pod.GetId()}
	if g.sandboxErr != nil {
		return sb, g.sandboxErr
	}
	sb.CgroupID = cgroupOf(pod)
	return sb, nil
}

func cgroupOf(pod *api.PodSandbox) uint64 {
	var id uint64
	_, _ = fmt.Sscanf(pod.GetId(), "sb%d", &id)
	return id
}

func (g *fakeGate) JoinAndMark(_ context.Context, sb Sandbox, _ sandboxpolicy.PodClassification, _ time.Time) ([]sandboxpolicy.PodSectionResult, error) {
	g.record("JoinAndMark %s", sb.ID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.markErr != nil {
		return nil, g.markErr
	}
	n := 0
	for _, c := range g.calls {
		if strings.HasPrefix(c, "JoinAndMark") {
			n++
		}
	}
	return g.marks[min(n-1, len(g.marks)-1)], nil
}

func (g *fakeGate) JoinUnselected(sb Sandbox) error {
	g.record("JoinUnselected %s", sb.ID)
	return g.joinErr
}

func (g *fakeGate) HoldsMark(types.UID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.holdsMark
}

func (g *fakeGate) PauseAlive(pod *api.PodSandbox) bool {
	g.record("PauseAlive %s", pod.GetId())
	return !g.dead[pod.GetId()]
}

func (g *fakeGate) Unmark(_ context.Context, sb Sandbox, _ sandboxpolicy.Seq, _ time.Time) error {
	g.record("Unmark %s", sb.ID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.unmarkErrs) == 0 {
		return nil
	}
	err := g.unmarkErrs[0]
	g.unmarkErrs = g.unmarkErrs[1:]
	return err
}

func (g *fakeGate) HoldUntilConfirmed(_ context.Context, sb Sandbox, _ sandboxpolicy.PodClassification, _ time.Time) ([]sandboxpolicy.PodSectionConfirmation, error) {
	g.record("Hold %s", sb.ID)
	return slices.Clone(g.confs), g.holdErr
}

func (g *fakeGate) ReleaseSandbox(_ context.Context, sb Sandbox, _ time.Time) error {
	g.record("Release %s %d", sb.ID, sb.CgroupID)
	return g.releaseErr
}

func (g *fakeGate) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	ids := make([]uint64, 0, len(proven))
	for id := range proven {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.synced = append(g.synced, fmt.Sprintf("%d:%v", epoch, ids))
}

func (g *fakeGate) SetNRIDisconnected(epoch uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.disconnects = append(g.disconnects, epoch)
}

func (g *fakeGate) Registration() error {
	g.record("Registration")
	return g.registerErr
}

var priv = sandboxpolicy.SectionPrivilege

func policyID(uid string) sandboxpolicy.PolicyIdentity {
	return sandboxpolicy.PolicyIdentity{UID: types.UID(uid), Kind: "SandboxPolicy", Namespace: "ns", Name: uid}
}

func sel(strict bool) sandboxpolicy.PodClassification {
	return sandboxpolicy.PodClassification{Class: sandboxpolicy.PodSelected, Strict: strict, Policies: []sandboxpolicy.PolicyIdentity{policyID("p1")},
		Sections: map[string]sandboxpolicy.SectionPlan{priv: {Digest: "d", Strict: strict}}, Seq: sandboxpolicy.Seq{Config: 1, Input: 1}}
}

func withShape(c sandboxpolicy.PodClassification, shape sandboxpolicy.PodShape) sandboxpolicy.PodClassification {
	c.Shape |= shape
	if shape&sandboxpolicy.ShapeSources != 0 {
		c.Sections = nil
	}
	return c
}

func withExec(c sandboxpolicy.PodClassification) sandboxpolicy.PodClassification {
	c.Exec = true
	return c
}

var (
	unselected = sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnselected, Reason: "unselected"}
	exempt     = sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnselected, Reason: "exempt", Exempt: true}
	exemptSel  = sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnselected, Reason: "exempt, but selected by SandboxPolicy ns/p1", Exempt: true, ExemptButSelected: true}
	unknownCls = sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnknown, Reason: "pod ns/pod (pod-uid) is not known"}
	brokenCls  = sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnknown, Reason: "SandboxPolicy ns/p1 is in scope and has an error: bad"}
)

func ok() []sandboxpolicy.PodSectionResult {
	return []sandboxpolicy.PodSectionResult{{Section: priv}}
}

func failed(err error) []sandboxpolicy.PodSectionResult {
	return []sandboxpolicy.PodSectionResult{{Section: priv, Err: err}}
}

func conf(state sandboxpolicy.PodSectionState, strict bool) []sandboxpolicy.PodSectionConfirmation {
	return []sandboxpolicy.PodSectionConfirmation{{Section: priv, State: state, Strict: strict, Reason: "test"}}
}

func testPod(id string) *api.PodSandbox {
	return &api.PodSandbox{Id: id, Uid: "pod-uid", Namespace: "ns", Name: "pod", Annotations: map[string]string{"sandbox": id}, Linux: &api.LinuxPodSandbox{CgroupParent: "kubepods-besteffort-podpod_uid.slice"}}
}

func testContainer(name string) *api.Container {
	return &api.Container{Id: "c-" + name, Name: name, Linux: &api.LinuxContainer{CgroupsPath: "kubepods-besteffort-podpod_uid.slice:cri-containerd:c-" + name}}
}

// configured returns a plugin configured with a 2 s request timeout.
func configured(t *testing.T, g Gate, alerts *[]Alert) *Plugin {
	t.Helper()
	p := newPlugin(g, Options{OnAlert: func(a Alert) { *alerts = append(*alerts, a) }})
	read := func() time.Duration { return 2 * time.Second }
	p.readTimeout.Store(&read)
	if _, err := p.Configure(t.Context(), "", "containerd", "v2.3.7"); err != nil {
		t.Fatal(err)
	}
	return p
}

// errTransportClosed stands for a transport error the runtime takes as
// fatal (ttrpc.ErrClosed and its kin): no reply may carry its identity.
var errTransportClosed = errors.New("ttrpc: closed")

// noFatal fails when err carries an error identity (defence in depth; see
// TestS5NoContextErrorIsWrapped): a context error or a
// ttrpc one, or any wrapped identity at all.
func noFatal(t *testing.T, err error) {
	t.Helper()
	for _, fatal := range []error{context.DeadlineExceeded, context.Canceled, errTransportClosed} {
		if errors.Is(err, fatal) {
			t.Fatalf("a reply carries %v: %v", fatal, err)
		}
	}
	if err != nil && errors.Unwrap(err) != nil {
		t.Fatalf("a reply wraps an error: %v", err)
	}
}

func hasAlert(alerts []Alert, kind string) bool {
	return slices.ContainsFunc(alerts, func(a Alert) bool { return a.Kind == kind })
}

// TestS5RunPodSandboxDecisions: RunPodSandbox's decision table.
func TestS5RunPodSandboxDecisions(t *testing.T) {
	errNotReady := errors.New("section privilege: instance not ready")
	tests := []struct {
		name       string
		class      sandboxpolicy.PodClassification
		marks      [][]sandboxpolicy.PodSectionResult
		sandboxErr error
		wantErr    string
		wantCalls  []string
		alert      string
		state      PodState
	}{
		{name: "unselected", class: unselected, wantCalls: []string{"JoinUnselected sb7", "Unmark sb7"}},
		{name: "exempt", class: exempt, wantCalls: []string{"JoinUnselected sb7", "Unmark sb7"}},
		{name: "exempt but selected alerts", class: exemptSel, wantCalls: []string{"JoinUnselected sb7", "Unmark sb7"}, alert: AlertExemptButSelected},
		{name: "unselected without a cgroup", class: unselected, sandboxErr: errors.New("no pause"), wantCalls: []string{"JoinUnselected sb7", "Unmark sb7"}},
		{name: "unknown", class: unknownCls, wantErr: "cannot be classified", wantCalls: []string{"JoinUnselected sb7"}, alert: AlertUnknownPod},
		{name: "broken policy", class: brokenCls, wantErr: "has an error", wantCalls: []string{"JoinUnselected sb7"}, alert: AlertBrokenPolicy},
		{name: "strict marked", class: sel(true), marks: [][]sandboxpolicy.PodSectionResult{ok()}, wantCalls: []string{"JoinAndMark sb7"}},
		{name: "audit marked", class: sel(false), marks: [][]sandboxpolicy.PodSectionResult{ok()}, wantCalls: []string{"JoinAndMark sb7"}},
		{name: "strict adopted entry", class: sel(true), marks: [][]sandboxpolicy.PodSectionResult{failed(sandboxpolicy.ErrPolicyEntry)}, wantCalls: []string{"JoinAndMark sb7"}},
		{name: "audit adopted entry", class: sel(false), marks: [][]sandboxpolicy.PodSectionResult{failed(sandboxpolicy.ErrPolicyEntry)}, wantCalls: []string{"JoinAndMark sb7"}},
		{name: "strict mark failed", class: sel(true), marks: [][]sandboxpolicy.PodSectionResult{failed(errNotReady)}, wantErr: "strict section privilege: mark failed", wantCalls: []string{"JoinAndMark sb7"}, alert: AlertSectionNotReady, state: StateFaulted},
		{name: "audit mark failed (D3a)", class: sel(false), marks: [][]sandboxpolicy.PodSectionResult{failed(errNotReady)}, wantErr: "refused (D3a)", wantCalls: []string{"JoinAndMark sb7"}, alert: AlertSectionNotReady, state: StateFaulted},
		{name: "section missing from the results", class: sel(true), marks: [][]sandboxpolicy.PodSectionResult{nil}, wantErr: "no mark result", wantCalls: []string{"JoinAndMark sb7"}, state: StateFaulted},
		{name: "strict cgroup unresolved", class: sel(true), marks: [][]sandboxpolicy.PodSectionResult{ok()}, sandboxErr: errors.New("pause process gone"), wantErr: "pause process gone", wantCalls: []string{"JoinAndMark sb7"}, state: StateFaulted},
		{name: "strict sources (D1)", class: withShape(sel(true), sandboxpolicy.ShapeSources), wantErr: "(D1)", wantCalls: []string{"JoinUnselected sb7"}, state: StateFaulted},
		{name: "strict different sets (D1)", class: withShape(sel(true), sandboxpolicy.ShapeDifferentSets), wantErr: "(D1)", wantCalls: []string{"JoinUnselected sb7"}, state: StateFaulted},
		{name: "strict exec (D2)", class: withExec(sel(true)), wantErr: "(D2)", wantCalls: []string{"JoinUnselected sb7"}, state: StateFaulted},
		{name: "audit sources: not start-gated", class: withShape(sel(false), sandboxpolicy.ShapeSources), wantCalls: []string{"JoinUnselected sb7"}, state: StateNotStartGated},
		{name: "audit exec: marked", class: withExec(sel(false)), marks: [][]sandboxpolicy.PodSectionResult{ok()}, wantCalls: []string{"JoinAndMark sb7"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGate{classes: []sandboxpolicy.PodClassification{tc.class}, marks: tc.marks, sandboxErr: tc.sandboxErr}
			var alerts []Alert
			p := configured(t, g, &alerts)
			err := p.RunPodSandbox(t.Context(), testPod("sb7"))
			noFatal(t, err)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			var calls []string
			for _, c := range g.calls {
				if !strings.HasPrefix(c, "Classify") && c != "Registration" {
					calls = append(calls, c)
				}
			}
			if !slices.Equal(calls, tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
			if tc.alert != "" && !hasAlert(alerts, tc.alert) {
				t.Fatalf("alerts = %v, want %s", alerts, tc.alert)
			}
			st := p.Status()
			switch {
			case tc.state == "" && len(st) != 0:
				t.Fatalf("status = %v, want none", st)
			case tc.state != "" && (len(st) != 1 || st[0].State != tc.state || !slices.Equal(st[0].Policies, []types.UID{"p1"})):
				t.Fatalf("status = %v, want %s for policy p1", st, tc.state)
			}
		})
	}
}

// TestS5CreateContainerDecisions: CreateContainer's decision table: the
// mark, the hold and the read-back (confirmDecision), per class and shape.
func TestS5CreateContainerDecisions(t *testing.T) {
	tests := []struct {
		name    string
		class   sandboxpolicy.PodClassification
		confs   []sandboxpolicy.PodSectionConfirmation
		holdErr error
		inPod   bool
		wantErr string
		hold    bool
		alert   string
		state   PodState
	}{
		{name: "strict confirmed", class: sel(true), confs: conf(sandboxpolicy.PodSectionConfirmed, true), hold: true},
		{name: "strict pending strict mark", class: sel(true), confs: conf(sandboxpolicy.PodSectionPending, true), holdErr: errors.New("start gate: the work deadline passed"), hold: true, state: StatePending},
		{name: "strict faulted", class: sel(true), confs: conf(sandboxpolicy.PodSectionFaulted, true), wantErr: "Strict section privilege is not confirmed", hold: true, state: StateFaulted},
		{name: "strict unavailable", class: sel(true), confs: conf(sandboxpolicy.PodSectionUnavailable, true), wantErr: "unavailable", hold: true, alert: AlertSectionNotReady, state: StateFaulted},
		{name: "strict class mismatch", class: sel(true), confs: conf(sandboxpolicy.PodSectionPending, false), wantErr: "the backend's plan is Audit", hold: true, state: StateFaulted},
		{name: "strict no confirmation at the deadline", class: sel(true), holdErr: errors.New("start gate: the work deadline passed"), wantErr: "not confirmed", hold: true, state: StateFaulted},
		{name: "strict other section only", class: sel(true), confs: []sandboxpolicy.PodSectionConfirmation{{Section: sandboxpolicy.SectionFile, State: sandboxpolicy.PodSectionConfirmed, Strict: true}}, wantErr: "no confirmation", hold: true, state: StateFaulted},
		{name: "audit confirmed", class: sel(false), confs: conf(sandboxpolicy.PodSectionConfirmed, false), hold: true},
		{name: "audit committed but unbound (D9a)", class: sel(false), confs: conf(sandboxpolicy.PodSectionPending, false), hold: true, state: StateAuditDegraded},
		{name: "audit read-back still strict (D9a residual)", class: sel(false), confs: []sandboxpolicy.PodSectionConfirmation{{Section: priv, State: sandboxpolicy.PodSectionFaulted, Reason: "read-back: the kernel entry is strict"}}, wantErr: "Audit section privilege is not confirmed", hold: true, state: StateFaulted},
		{name: "audit section not ready (D3a)", class: sel(false), confs: []sandboxpolicy.PodSectionConfirmation{{Section: priv, State: sandboxpolicy.PodSectionFaulted, Reason: "instance not ready"}}, wantErr: "not confirmed", hold: true, alert: AlertSectionNotReady, state: StateFaulted},
		{name: "audit unavailable (D3a)", class: sel(false), confs: conf(sandboxpolicy.PodSectionUnavailable, false), wantErr: "(D1/D3a)", hold: true, state: StateFaulted},
		{name: "strict container in the pod cgroup (D1)", class: sel(true), inPod: true, wantErr: "(D1)", state: StateFaulted},
		{name: "audit container in the pod cgroup", class: sel(false), inPod: true, confs: conf(sandboxpolicy.PodSectionPending, false), hold: true, state: StateAuditDegraded},
		{name: "strict exec (D2)", class: withExec(sel(true)), wantErr: "(D2)", state: StateFaulted},
		{name: "strict sources (D1)", class: withShape(sel(true), sandboxpolicy.ShapeSources), wantErr: "(D1)", state: StateFaulted},
		{name: "audit sources: not start-gated", class: withShape(sel(false), sandboxpolicy.ShapeSources), state: StateNotStartGated},
		{name: "unknown", class: unknownCls, wantErr: "cannot be classified"},
		{name: "unselected", class: unselected},
	}
	for _, tc := range tests {
		for _, start := range []bool{false, true} {
			name := tc.name + "/create"
			if start {
				name = tc.name + "/start"
			}
			t.Run(name, func(t *testing.T) {
				g := &fakeGate{classes: []sandboxpolicy.PodClassification{tc.class}, marks: [][]sandboxpolicy.PodSectionResult{ok()}, confs: tc.confs, holdErr: tc.holdErr}
				var alerts []Alert
				p := configured(t, g, &alerts)
				ctr := testContainer("app")
				if tc.inPod {
					ctr.Linux.CgroupsPath = ""
				}
				var err error
				if start {
					err = p.StartContainer(t.Context(), testPod("sb7"), ctr)
				} else {
					_, _, err = p.CreateContainer(t.Context(), testPod("sb7"), ctr)
				}
				noFatal(t, err)
				if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if got := g.count("Hold") == 1; got != tc.hold {
					t.Fatalf("held = %v, want %v (%v)", got, tc.hold, g.calls)
				}
				// CreateContainer marks a pod it holds; StartContainer never marks.
				if marks := g.count("JoinAndMark"); start && marks != 0 || !start && marks != g.count("Hold") {
					t.Fatalf("JoinAndMark calls = %d (start %v): %v", marks, start, g.calls)
				}
				if tc.alert != "" && !hasAlert(alerts, tc.alert) {
					t.Fatalf("alerts = %v, want %s", alerts, tc.alert)
				}
				st := p.Status()
				if tc.state == "" && len(st) != 0 || tc.state != "" && (len(st) != 1 || st[0].State != tc.state) {
					t.Fatalf("status = %v, want %q", st, tc.state)
				}
			})
		}
	}
}

// TestS5CreateMarkFailureRefuses: a failed mark at CreateContainer refuses
// before the hold, Strict and Audit (D3a).
func TestS5CreateMarkFailureRefuses(t *testing.T) {
	for _, strict := range []bool{true, false} {
		g := &fakeGate{classes: []sandboxpolicy.PodClassification{sel(strict)}, marks: [][]sandboxpolicy.PodSectionResult{failed(errors.New("busy"))}}
		var alerts []Alert
		p := configured(t, g, &alerts)
		_, _, err := p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
		noFatal(t, err)
		if err == nil || !strings.Contains(err.Error(), "not marked") || g.count("Hold") != 0 {
			t.Fatalf("strict %v: err = %v, calls %v", strict, err, g.calls)
		}
	}
}

// TestS5ExemptContainerUnderPodMark: the container-form exemption under a
// pod mark (S4 review v1 7(a)): a Strict pod refuses the exempt container,
// an Audit, Unselected or exempt pod admits it, an Unknown pod refuses it.
func TestS5ExemptContainerUnderPodMark(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pod     sandboxpolicy.PodClassification
		wantErr string
	}{
		{"strict pod", sel(true), "its pod is Strict"},
		{"audit pod", sel(false), ""},
		{"unselected pod", unselected, ""},
		{"exempt pod", exempt, ""},
		{"unknown pod", unknownCls, "cannot be classified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGate{byContainer: map[string]sandboxpolicy.PodClassification{"app": exempt, "": tc.pod}}
			var alerts []Alert
			p := configured(t, g, &alerts)
			_, _, err := p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
			noFatal(t, err)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if g.count("JoinAndMark") != 0 || g.count("Hold") != 0 || g.count("Unmark") != 0 {
				t.Fatalf("an exempt container changed the pod's mark: %v", g.calls)
			}
		})
	}
}

// TestS5UnselectedCreateUnmarks: a pod that turned Unselected loses the
// mark the gate wrote; a failed unmark refuses.
func TestS5UnselectedCreateUnmarks(t *testing.T) {
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{unselected}, unmarkErrs: []error{errors.New("instance not ready")}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	_, _, err := p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
	noFatal(t, err)
	if err == nil || !strings.Contains(err.Error(), "removing its mark failed") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app")); err != nil {
		t.Fatal(err)
	}
}

// TestS5StaleRetryOnce: a write refused as stale (ErrStaleSequence) is
// retried once with a fresh classification; a second stale refusal fails.
func TestS5StaleRetryOnce(t *testing.T) {
	stale := failed(fmt.Errorf("section privilege: %w", sandboxpolicy.ErrStaleSequence))
	for _, tc := range []struct {
		name     string
		marks    [][]sandboxpolicy.PodSectionResult
		markErr  error
		wantErr  bool
		classify int
	}{
		{name: "stale then ok", marks: [][]sandboxpolicy.PodSectionResult{stale, ok()}, classify: 2},
		{name: "stale twice", marks: [][]sandboxpolicy.PodSectionResult{stale, stale}, wantErr: true, classify: 2},
	} {
		for _, handler := range []string{"run", "create"} {
			t.Run(tc.name+"/"+handler, func(t *testing.T) {
				g := &fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, marks: tc.marks, confs: conf(sandboxpolicy.PodSectionConfirmed, true)}
				var alerts []Alert
				p := configured(t, g, &alerts)
				var err error
				if handler == "run" {
					err = p.RunPodSandbox(t.Context(), testPod("sb7"))
				} else {
					_, _, err = p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
				}
				noFatal(t, err)
				if (err != nil) != tc.wantErr {
					t.Fatalf("err = %v, want error %v", err, tc.wantErr)
				}
				if g.classified != tc.classify || g.count("JoinAndMark") != 2 {
					t.Fatalf("classified %d, marked %d; want %d and 2", g.classified, g.count("JoinAndMark"), tc.classify)
				}
			})
		}
	}
	// A stale unmark is retried once too.
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{unselected}, unmarkErrs: []error{sandboxpolicy.ErrStaleSequence}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	if err := p.RunPodSandbox(t.Context(), testPod("sb7")); err != nil || g.count("Unmark") != 2 || g.classified != 2 {
		t.Fatalf("err = %v, calls %v", err, g.calls)
	}
}

// TestS5NoContextErrorIsWrapped: whatever the gate returns (context errors,
// transport errors, wrapped or joined), no reply carries an error identity
// (reply, defence in depth), and every path still refuses. This is not the
// fatal-path proof: over the wire ttrpc sends any reply error as a status
// that containerd never takes as fatal. The fatal path is an overrun
// (TestS5WireRegistrationRefusalOverrunReconnect, startgate_vmtest).
func TestS5NoContextErrorIsWrapped(t *testing.T) {
	for _, cause := range []error{
		context.DeadlineExceeded, context.Canceled, errTransportClosed,
		fmt.Errorf("mark: %w", context.DeadlineExceeded),
		errors.Join(sandboxpolicy.ErrStaleSequence, context.Canceled),
	} {
		g := &fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, markErr: cause, holdErr: cause, releaseErr: cause, confs: nil}
		var alerts []Alert
		p := configured(t, g, &alerts)
		_, _, err := p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
		if err == nil {
			t.Fatalf("%v: create admitted", cause)
		}
		noFatal(t, err)
		err = p.StartContainer(t.Context(), testPod("sb7"), testContainer("app"))
		if err == nil {
			t.Fatalf("%v: start admitted", cause)
		}
		noFatal(t, err)
		err = p.RunPodSandbox(t.Context(), testPod("sb7"))
		if err == nil {
			t.Fatalf("%v: run admitted", cause)
		}
		noFatal(t, err)
		err = p.RemovePodSandbox(t.Context(), testPod("sb7"))
		if err == nil {
			t.Fatalf("%v: the release error was dropped", cause)
		}
		noFatal(t, err)
		_, err = p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb7")}, nil)
		if err == nil {
			t.Fatalf("%v: Synchronize completed", cause)
		}
		noFatal(t, err)
		g.unmarkErrs = []error{cause}
		g.classes = []sandboxpolicy.PodClassification{unselected}
		g.classified = 0
		_, _, err = p.CreateContainer(t.Context(), testPod("sb7"), testContainer("app"))
		if err == nil {
			t.Fatalf("%v: a failed unmark admitted", cause)
		}
		noFatal(t, err)
	}
	// A handler context that is already past its deadline: a reply error
	// (no work budget), never the context's own error.
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{ok()}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	err := p.RunPodSandbox(ctx, testPod("sb7"))
	if err == nil || g.count("JoinAndMark") != 0 {
		t.Fatalf("err = %v, calls %v", err, g.calls)
	}
	noFatal(t, err)
	_, _, err = p.CreateContainer(ctx, testPod("sb7"), testContainer("app"))
	noFatal(t, err)
	err = p.RemovePodSandbox(ctx, testPod("sb7"))
	noFatal(t, err)
	_, err = p.Synchronize(ctx, nil, nil)
	noFatal(t, err)
}

// TestS5SynchronizeD10a: one Unknown or unmarkable Selected sandbox fails
// Synchronize (no SetNRISynced); a complete one reports every sandbox and
// records proven: the Unselected pods' cgroups, never one a Selected
// sandbox also names.
func TestS5SynchronizeD10a(t *testing.T) {
	pods := []*api.PodSandbox{testPod("sb1"), testPod("sb2")}
	for _, tc := range []struct {
		name    string
		byID    map[string]sandboxpolicy.PodClassification
		marks   [][]sandboxpolicy.PodSectionResult
		wantErr string
		synced  string
	}{
		{name: "complete", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{ok()}, synced: "5:[1]"},
		{name: "audit marked", byID: map[string]sandboxpolicy.PodClassification{"sb1": exempt, "sb2": sel(false)}, marks: [][]sandboxpolicy.PodSectionResult{ok()}, synced: "5:[1]"},
		{name: "audit not start-gated", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": withShape(sel(false), sandboxpolicy.ShapeSources)}, synced: "5:[1]"},
		{name: "one unknown", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": unknownCls}, wantErr: "D10a"},
		{name: "one unmarkable strict", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{failed(errors.New("busy"))}, wantErr: "D10a"},
		{name: "one unmarkable audit", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": sel(false)}, marks: [][]sandboxpolicy.PodSectionResult{failed(errors.New("busy"))}, wantErr: "D10a"},
		{name: "one strict sources", byID: map[string]sandboxpolicy.PodClassification{"sb1": unselected, "sb2": withShape(sel(true), sandboxpolicy.ShapeSources)}, wantErr: "D10a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &classifyByID{fakeGate: fakeGate{marks: tc.marks}, byID: tc.byID}
			var alerts []Alert
			p := newPlugin(g, Options{OnAlert: func(a Alert) { alerts = append(alerts, a) }})
			read := func() time.Duration { return 2 * time.Second }
			p.readTimeout.Store(&read)
			if _, err := p.Configure(t.Context(), "", "containerd", "v2.3.7"); err != nil {
				t.Fatal(err)
			}
			p.epoch.Store(5)
			_, err := p.Synchronize(t.Context(), pods, nil)
			noFatal(t, err)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			want := []string(nil)
			if tc.synced != "" {
				want = []string{tc.synced}
			}
			if !slices.Equal(g.synced, want) {
				t.Fatalf("SetNRISynced = %v, want %v", g.synced, want)
			}
			// Every sandbox was reported, whatever the outcome.
			for _, id := range []string{"sb1", "sb2"} {
				if g.count("JoinUnselected "+id)+g.count("JoinAndMark "+id) == 0 {
					t.Fatalf("sandbox %s was not reported: %v", id, g.calls)
				}
			}
		})
	}
	// A cgroup both an Unselected and a Selected sandbox name is never proven.
	g := &classifyByID{byID: map[string]sandboxpolicy.PodClassification{"sb3": unselected, "sb3-again": sel(true)}, fakeGate: fakeGate{marks: [][]sandboxpolicy.PodSectionResult{ok()}}}
	p := newPlugin(g, Options{})
	read := func() time.Duration { return 2 * time.Second }
	p.readTimeout.Store(&read)
	if _, err := p.Configure(t.Context(), "", "", ""); err != nil {
		t.Fatal(err)
	}
	p.epoch.Store(6)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb3"), testPod("sb3-again")}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.synced, []string{"6:[]"}) {
		t.Fatalf("SetNRISynced = %v, want 6:[]", g.synced)
	}
}

// classifyByID classifies each sandbox by its ID (Synchronize tests).
type classifyByID struct {
	fakeGate
	byID map[string]sandboxpolicy.PodClassification
}

func (g *classifyByID) Classify(ctx context.Context, req sandboxpolicy.ClassifyRequest) sandboxpolicy.PodClassification {
	g.record("Classify")
	// The request names the pod, not the sandbox: testPod annotates each
	// sandbox with its ID.
	return g.byID[req.Pod.Annotations["sandbox"]]
}

// TestS5EpochAndDisconnect: Synchronize records the connection epoch it ran
// on; a disconnect is passed on with its epoch; a stale completion is the
// backend's to ignore (it compares the epochs).
func TestS5EpochAndDisconnect(t *testing.T) {
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{unselected}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	p.epoch.Store(1)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb4")}, nil); err != nil {
		t.Fatal(err)
	}
	p.gate.SetNRIDisconnected(1)
	p.epoch.Store(2)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{testPod("sb4")}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.synced, []string{"1:[4]", "2:[4]"}) || !slices.Equal(g.disconnects, []uint64{1}) {
		t.Fatalf("synced %v, disconnects %v", g.synced, g.disconnects)
	}
	// Configure refuses (no registration) when the registration gate does
	// not hold, or the runtime's timeout leaves no work budget.
	g.registerErr = errors.New("informers not synced")
	if _, err := p.Configure(t.Context(), "", "", ""); err == nil {
		t.Fatal("Configure registered with the registration gate closed")
	}
	g.registerErr = nil
	short := func() time.Duration { return 2 * ReturnMargin }
	p.readTimeout.Store(&short)
	if _, err := p.Configure(t.Context(), "", "", ""); err == nil {
		t.Fatal("Configure accepted a request timeout with no work budget")
	}
	// The subscription: exactly the four start gate events.
	long := func() time.Duration { return 2 * time.Second }
	p.readTimeout.Store(&long)
	mask, err := p.Configure(t.Context(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var want api.EventMask
	want.Set(api.Event_RUN_POD_SANDBOX, api.Event_CREATE_CONTAINER, api.Event_START_CONTAINER, api.Event_REMOVE_POD_SANDBOX)
	if mask != want {
		t.Fatalf("events %s, want %s", mask.PrettyString(), want.PrettyString())
	}
}

// TestS5RemovePodSandboxReleases: RemovePodSandbox releases the sandbox
// (podGate.ReleaseSandbox tombstones it first) and forgets the pod's status.
func TestS5RemovePodSandboxReleases(t *testing.T) {
	g := &fakeGate{classes: []sandboxpolicy.PodClassification{sel(true)}, marks: [][]sandboxpolicy.PodSectionResult{ok()}}
	var alerts []Alert
	p := configured(t, g, &alerts)
	if err := p.RunPodSandbox(t.Context(), testPod("sb9")); err != nil {
		t.Fatal(err)
	}
	p.setStatus(testPod("sb9"), sel(true), StateFaulted, "a refused create")
	if len(p.Status()) != 1 {
		t.Fatalf("status %v", p.Status())
	}
	if err := p.RemovePodSandbox(t.Context(), testPod("sb9")); err != nil {
		t.Fatal(err)
	}
	if g.count("Release sb9 9") != 1 || len(p.Status()) != 0 {
		t.Fatalf("calls %v, status %v", g.calls, p.Status())
	}
}

// TestS5ContainerInPodCgroup: the D1 shape "container in the pod cgroup",
// fail-closed for a path the gate cannot place.
func TestS5ContainerInPodCgroup(t *testing.T) {
	for _, tc := range []struct {
		parent, path string
		want         bool
	}{
		{"kubepods-besteffort-podu.slice", "kubepods-besteffort-podu.slice:cri-containerd:abc", false},
		{"kubepods-besteffort-podu.slice", "kubepods-besteffort-podother.slice:cri-containerd:abc", true},
		{"kubepods-besteffort-podu.slice", "kubepods-besteffort-podu.slice::abc", true},
		{"kubepods-besteffort-podu.slice", "kubepods-besteffort-podu.slice", true},
		{"/kubepods/besteffort/podu", "/kubepods/besteffort/podu/abc", false},
		{"/kubepods/besteffort/podu", "/kubepods/besteffort/podu", true},
		{"/kubepods/besteffort/podu", "/kubepods/besteffort/podu/abc/def", true},
		{"/kubepods/besteffort/podu", "/kubepods/besteffort/podu/../x", true},
		{"", "/kubepods/besteffort/podu/abc", true},
		{"/kubepods/besteffort/podu", "", true},
	} {
		pod := &api.PodSandbox{Linux: &api.LinuxPodSandbox{CgroupParent: tc.parent}}
		ctr := &api.Container{Linux: &api.LinuxContainer{CgroupsPath: tc.path}}
		if got := ContainerInPodCgroup(pod, ctr); got != tc.want {
			t.Errorf("parent %q path %q: %v, want %v", tc.parent, tc.path, got, tc.want)
		}
	}
}

// TestS5AlertsAreRateLimited: one alert per kind and key per interval.
func TestS5AlertsAreRateLimited(t *testing.T) {
	var alerts []Alert
	p := newPlugin(&fakeGate{}, Options{OnAlert: func(a Alert) { alerts = append(alerts, a) }})
	p.alert(AlertBrokenPolicy, "a", "x")
	p.alert(AlertBrokenPolicy, "a", "y")
	p.alert(AlertBrokenPolicy, "b", "z")
	p.alert(AlertSectionNotReady, "a", "w")
	if len(alerts) != 3 {
		t.Fatalf("alerts %v", alerts)
	}
}
