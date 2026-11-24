package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// A sequence is newer when both components are at least the last's and one
// is greater; an incomparable pair is not newer in either direction. A
// tightening applies at a newer or equal sequence, a loosening only at a
// newer one.
func TestSeqAdmits(t *testing.T) {
	last := Seq{Config: 5, Input: 5}
	tests := []struct {
		name            string
		seq             Seq
		order, reverse  SeqOrder
		tighten, loosen bool
	}{
		{name: "equal", seq: Seq{5, 5}, order: SeqEqual, reverse: SeqEqual, tighten: true},
		{name: "both newer", seq: Seq{6, 6}, order: SeqNewer, reverse: SeqOlder, tighten: true, loosen: true},
		{name: "config newer", seq: Seq{6, 5}, order: SeqNewer, reverse: SeqOlder, tighten: true, loosen: true},
		{name: "epoch newer", seq: Seq{5, 6}, order: SeqNewer, reverse: SeqOlder, tighten: true, loosen: true},
		{name: "both older", seq: Seq{4, 4}, order: SeqOlder, reverse: SeqNewer},
		{name: "config older", seq: Seq{4, 5}, order: SeqOlder, reverse: SeqNewer},
		{name: "incomparable, config newer", seq: Seq{6, 4}, order: SeqIncomparable, reverse: SeqIncomparable},
		{name: "incomparable, epoch newer", seq: Seq{4, 6}, order: SeqIncomparable, reverse: SeqIncomparable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.seq.Compare(last); got != tt.order {
				t.Fatalf("Compare %v, want %v", got, tt.order)
			}
			if got := last.Compare(tt.seq); got != tt.reverse {
				t.Fatalf("reverse Compare %v, want %v", got, tt.reverse)
			}
			if got := tt.seq.Admits(last, false); got != tt.tighten {
				t.Fatalf("a tightening applies %v, want %v", got, tt.tighten)
			}
			if got := tt.seq.Admits(last, true); got != tt.loosen {
				t.Fatalf("a loosening applies %v, want %v", got, tt.loosen)
			}
		})
	}
}

// gateBackend is a section backend with a pod gate that records its calls.
type gateBackend struct {
	fakeBackend
	marked, ensured, released []types.UID
	markErr                   error
	confirm                   PodSectionConfirmation
	gate                      bool
	epoch                     uint64
	proven                    map[uint64]bool
	gone                      func(uint64) bool
	unmarked                  []types.UID
	disconnected              uint64
	seq                       *Seq
}

func (g *gateBackend) MarkPod(_ context.Context, pod PodBinding, _ Seq) error {
	g.marked = append(g.marked, pod.PodUID)
	return g.markErr
}
func (g *gateBackend) EnsurePodBound(_ context.Context, uid types.UID) error {
	g.ensured = append(g.ensured, uid)
	return nil
}
func (g *gateBackend) ConfirmPod(types.UID, uint64, Plan) PodSectionConfirmation { return g.confirm }
func (g *gateBackend) ReleasePod(_ context.Context, uid types.UID, _ uint64) error {
	g.released = append(g.released, uid)
	return nil
}
func (g *gateBackend) BindPodsAt(_ context.Context, _ []PodBinding, seq Seq) error {
	g.seq = &seq
	return nil
}
func (g *gateBackend) UnmarkPod(_ context.Context, uid types.UID, _ uint64, _ Seq) error {
	g.unmarked = append(g.unmarked, uid)
	return nil
}
func (g *gateBackend) SetStartGate(enabled bool) { g.gate = enabled }
func (g *gateBackend) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	g.epoch, g.proven = epoch, proven
}
func (g *gateBackend) SetCgroupGone(gone func(uint64) bool) { g.gone = gone }
func (g *gateBackend) SetNRIDisconnected(epoch uint64)      { g.disconnected = epoch }

// The section backend asks each section whose policies the plan has, and
// only those. An unavailable section, or one without a pod gate, is
// Unavailable for ConfirmPod and a failed result for MarkPod: never
// confirmed, never skipped. The class of each section comes from the plan.
func TestSectionBackendPodGate(t *testing.T) {
	ctx := context.Background()
	exec := &fakeBackend{plans: map[string]Plan{}}
	privilege := &gateBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}},
		confirm: PodSectionConfirmation{Section: SectionPrivilege, State: PodSectionConfirmed, Strict: true}}
	network := &fakeBackend{plans: map[string]Plan{}} // no pod gate
	s, err := NewSectionBackend(exec, privilege, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.WithNetwork(network, nil) // the file section stays unavailable
	strictPriv := CompiledPolicy{Identity: PolicyIdentity{UID: "p"}, Mode: api.ModeEnforce, Privilege: privilegeSection(api.ActionDeny)}
	auditNet := CompiledPolicy{Identity: PolicyIdentity{UID: "n"}, Mode: api.ModeAudit, Network: &NetworkPlan{}}
	auditFile := CompiledPolicy{Identity: PolicyIdentity{UID: "f"}, Mode: api.ModeAudit, File: &FilePlan{}}
	execOnly := CompiledPolicy{Identity: PolicyIdentity{UID: "e"}, Mode: api.ModeEnforce, Exec: api.ExecSection{Default: api.ActionDeny}}
	plan := Plan{Policies: []CompiledPolicy{strictPriv, auditNet, auditFile, execOnly}}
	pod := PodBinding{PodUID: "u", CgroupID: 7, CgroupPath: "/kubepods/podu", Plan: plan}

	got := s.ConfirmPod("u", 7, plan)
	want := map[string]struct {
		state  PodSectionState
		strict bool
	}{
		SectionPrivilege: {PodSectionConfirmed, true},
		SectionNetwork:   {PodSectionUnavailable, false},
		SectionFile:      {PodSectionUnavailable, false},
	}
	if len(got) != len(want) {
		t.Fatalf("ConfirmPod: %+v, want one answer per section of the plan", got)
	}
	for _, c := range got {
		w, ok := want[c.Section]
		if !ok || c.State != w.state || c.Strict != w.strict {
			t.Fatalf("ConfirmPod %s: %+v, want %+v", c.Section, c, w)
		}
		if c.State == PodSectionUnavailable && c.Reason == "" {
			t.Fatalf("an unavailable section names why: %+v", c)
		}
	}
	marks := s.MarkPod(ctx, pod, Seq{1, 1})
	if len(marks) != 3 || len(privilege.marked) != 1 {
		t.Fatalf("MarkPod: %+v, privilege marked %v", marks, privilege.marked)
	}
	for _, r := range marks {
		if (r.Section == SectionPrivilege) != (r.Err == nil) {
			t.Fatalf("MarkPod %s: %v (only privilege can mark)", r.Section, r.Err)
		}
		if r.Strict != (r.Section == SectionPrivilege) {
			t.Fatalf("MarkPod %s: Strict %v", r.Section, r.Strict)
		}
	}
	privilege.markErr = ErrStaleSequence
	if marks := s.MarkPod(ctx, pod, Seq{1, 1}); !errors.Is(marks[0].Err, ErrStaleSequence) || marks[0].Section != SectionPrivilege {
		t.Fatalf("a refused mark: %+v", marks)
	}
	if r := s.EnsurePodBound(ctx, "u", plan); len(r) != 3 || len(privilege.ensured) != 1 {
		t.Fatalf("EnsurePodBound: %+v", r)
	}
	// A plan with no section policy asks nothing (exec has its own path).
	if got := s.ConfirmPod("u", 7, Plan{Policies: []CompiledPolicy{execOnly}}); len(got) != 0 {
		t.Fatalf("an exec-only plan: %+v", got)
	}
	if err := s.ReleasePod(ctx, "u", 7); err != nil || len(privilege.released) != 1 {
		t.Fatalf("ReleasePod: %v %v", err, privilege.released)
	}
	if err := s.BindPodsAt(ctx, nil, Seq{3, 4}); err != nil || privilege.seq == nil || *privilege.seq != (Seq{3, 4}) {
		t.Fatalf("BindPodsAt: %v %v", err, privilege.seq)
	}
	s.SetStartGate(true)
	s.SetNRISynced(3, map[uint64]bool{7: true})
	s.SetCgroupGone(func(uint64) bool { return false })
	s.SetNRIDisconnected(5)
	if privilege.disconnected != 5 {
		t.Fatal("the disconnect reaches the section")
	}
	if err := s.UnmarkPod(ctx, "u", 7, Seq{4, 4}); err != nil || len(privilege.unmarked) != 1 {
		t.Fatalf("UnmarkPod: %v %v", err, privilege.unmarked)
	}
	if !privilege.gate || privilege.epoch != 3 || !privilege.proven[7] || privilege.gone == nil {
		t.Fatal("the gate settings reach the section")
	}
	// The privilege section unavailable (its image not configured).
	s.set(SectionPrivilege, nil, errors.New("no privilege image"), "PrivilegeNotConfigured", "")
	for _, c := range s.ConfirmPod("u", 7, plan) {
		if c.Section == SectionPrivilege && (c.State != PodSectionUnavailable || !strings.Contains(c.Reason, "no privilege image")) {
			t.Fatalf("an unavailable section is never confirmed: %+v", c)
		}
	}
}

// The previous run's pod marks (no policy) are reported to every policy of
// their section, never hidden and never "policies not known".
func TestStatusAdoptedPendingMarks(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	r.adopted = []AdoptedSlot{{Section: SectionPrivilege, Slot: 0xFFFFFFFF, Bindings: 2, PendingMark: true}}
	var found *metav1.Condition
	conds := c.report(p, nil).Status.Conditions
	for i := range conds {
		if conds[i].Type == "AdoptedLastGood" {
			found = &conds[i]
		}
	}
	if found == nil || !strings.Contains(found.Message, "2 pod marks of the previous run") || strings.Contains(found.Message, "not known") {
		t.Fatalf("pending marks: %+v", conds)
	}
	r.adopted[0].Section = SectionNetwork
	for _, cond := range c.report(p, nil).Status.Conditions {
		if cond.Type == "AdoptedLastGood" {
			t.Fatalf("marks of another section must not show: %+v", cond)
		}
	}
}

// staleGate refuses every BindPodsAt write as stale, or fails with err.
type staleGate struct {
	gateBackend
	err error
}

func (g *staleGate) BindPodsAt(context.Context, []PodBinding, Seq) error { return g.err }

// S2 review v2, LOW 8: a stale write (ordinary race traffic) does not hold
// the section's Settle back; any other failure does.
func TestSectionBackendStaleWriteDoesNotFailTheSection(t *testing.T) {
	ctx := context.Background()
	stale := fmt.Errorf("privilege pod ns/u: %w", ErrStaleSequence)
	for _, tt := range []struct {
		name   string
		err    error
		failed bool
	}{
		{name: "none", err: nil},
		{name: "stale", err: stale},
		{name: "two stale", err: errors.Join(stale, nil, stale)},
		{name: "stale and a bind failure", err: errors.Join(stale, errors.New("map full")), failed: true},
		{name: "a bind failure", err: errors.New("map full"), failed: true},
		{name: "stale wrapped once", err: fmt.Errorf("section: %w", stale)},
		{name: "a wrapped join of stale and a bind failure", err: fmt.Errorf("section: %w", errors.Join(stale, errors.New("map full"))), failed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := &staleGate{gateBackend: gateBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}, err: tt.err}
			s, err := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, g, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.BindPodsAt(ctx, nil, Seq{1, 1})
			if s.sections[0].podFailed != tt.failed {
				t.Fatalf("podFailed %v, want %v", s.sections[0].podFailed, tt.failed)
			}
		})
	}
}
