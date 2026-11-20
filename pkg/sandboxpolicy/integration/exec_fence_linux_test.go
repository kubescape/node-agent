//go:build linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	rf "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type runtimeFenceFake struct {
	state     rf.PodState
	snapshot  rf.Snapshot
	err       error
	moved     []rf.ChildRef
	sealed    []rf.ChildRef
	members   []rf.PodMember
	publishes int
	withdrawn int
}

func (f *runtimeFenceFake) PublishCensus(_ *os.File, uid, revision uint64, mode rf.Mode, members []rf.PodMember) (rf.PodRef, error) {
	f.publishes++
	f.members = members
	f.state.PodRef = rf.PodRef{ID: 10, UIDHash: uid, Revision: revision + 1}
	f.state.Fallback = mode
	return f.state.PodRef, f.err
}
func (f *runtimeFenceFake) ReadPod(uint64) (rf.PodState, bool, error) {
	return f.state, f.state.Revision != 0, f.err
}
func (f *runtimeFenceFake) RefenceChild(p rf.PodRef, c rf.ChildRef) (rf.PodRef, error) {
	f.sealed = append(f.sealed, c)
	p.Revision++
	return p, f.err
}
func (f *runtimeFenceFake) MoveChild(p rf.PodRef, c rf.ChildRef, g uint64) (rf.PodRef, error) {
	f.moved = append(f.moved, c)
	p.Revision++
	return p, f.err
}
func (f *runtimeFenceFake) CommitPolicyWithdrawal(p rf.PodRef, _ rf.ChildRef) (rf.PodRef, error) {
	f.withdrawn++
	p.Revision++
	return p, f.err
}
func (f *runtimeFenceFake) DeactivateExecScope(p rf.PodRef) (rf.PodRef, error) {
	p.Revision++
	return p, f.err
}
func (f *runtimeFenceFake) Arm() error                     { f.snapshot.LiveIncarnation = 0; return f.err }
func (f *runtimeFenceFake) Snapshot() (rf.Snapshot, error) { return f.snapshot, f.err }
func (f *runtimeFenceFake) Close() error                   { return f.err }

type fenceTestLease struct{}

func (fenceTestLease) Check() error { return nil }
func (fenceTestLease) Close() error { return nil }

type fenceTestValidator struct{}

func (fenceTestValidator) Acquire(context.Context, sandboxpolicy.Binding) (igbackend.Lease, error) {
	return fenceTestLease{}, nil
}

type fenceTestAttester struct {
	generation uint64
	err        error
}

func (a fenceTestAttester) AttestFenceGeneration(context.Context, sandboxpolicy.Binding, string) (uint64, error) {
	return a.generation, a.err
}
func testFenceManager() (*ExecFenceManager, *runtimeFenceFake, sandboxpolicy.Binding) {
	f := &runtimeFenceFake{snapshot: rf.Snapshot{LiveIncarnation: 1, Owner: 1}}
	m := &ExecFenceManager{kernel: f, validator: fenceTestValidator{}, pods: map[uint64]rf.PodRef{}, bindings: map[uint64]fenceBinding{}, scope: map[uint64]bool{}}
	m.open = func(b sandboxpolicy.Binding) (*FenceCgroups, error) {
		return &FenceCgroups{PodID: 10, ContainerID: b.CgroupID}, nil
	}
	return m, f, sandboxpolicy.Binding{PodUID: "pod", ContainerID: "container", CgroupID: 11, ContainerName: "app"}
}
func fenceTestPlan(mode api.PolicyMode) sandboxpolicy.Plan {
	return sandboxpolicy.Plan{Revision: "r", Policies: []sandboxpolicy.CompiledPolicy{{Identity: sandboxpolicy.PolicyIdentity{UID: "policy"}, Revision: "p", Mode: mode, Exec: api.ExecSection{Default: "deny"}}}}
}
func TestExecFencePrepareMixedAndExactHandover(t *testing.T) {
	m, f, b := testFenceManager()
	other := b
	other.CgroupID = 12
	other.ContainerID = "sibling"
	cs := []sandboxpolicy.ExecFenceCandidate{{Binding: b, Plan: fenceTestPlan("enforce"), Known: true, Scope: true, MayStrict: true}, {Binding: other, Plan: fenceTestPlan("audit"), Known: true, Scope: true}}
	if err := m.Prepare(context.Background(), cs); err != nil {
		t.Fatal(err)
	}
	if f.publishes != 1 || f.state.Fallback != rf.Strict || len(f.members) != 2 || f.members[0].Mode != rf.Strict || f.members[1].Mode != rf.Audit {
		t.Fatalf("non-atomic mixed census: %+v", f)
	}
	m.SetAttester(fenceTestAttester{generation: 42})
	if err := m.VerifyAndMove(context.Background(), b, "r"); err != nil {
		t.Fatal(err)
	}
	if len(f.moved) != 1 || f.moved[0].ID != 11 {
		t.Fatalf("wrong handover: %v", f.moved)
	}
}
func TestExecFenceRetainsLastGoodAndRejectsCrossClass(t *testing.T) {
	for _, tc := range []struct {
		retained rf.Mode
		want     api.PolicyMode
	}{{rf.Strict, api.ModeAudit}, {rf.Audit, api.ModeEnforce}} {
		t.Run(string(tc.want), func(t *testing.T) {
			m, f, b := testFenceManager()
			f.state = rf.PodState{PodRef: rf.PodRef{ID: 10, UIDHash: fenceHash("pod"), Revision: 2}, Fallback: rf.Strict, Children: []rf.ChildState{{ChildRef: rf.ChildRef{ID: 11, Identity: fenceBindingID(b)}, Mode: tc.retained, Owner: 1, Generation: 5}}}
			c := sandboxpolicy.ExecFenceCandidate{Binding: b, Plan: fenceTestPlan(tc.want), Known: true, Scope: true}
			if err := m.Prepare(t.Context(), []sandboxpolicy.ExecFenceCandidate{c}); err != nil {
				t.Fatal(err)
			}
			if f.members[0].Mode != tc.retained {
				t.Fatal("last-good class changed")
			}
			if err := m.BeforeReplace(t.Context(), b, "r"); err == nil {
				t.Fatal("cross-class native publication authorized")
			}
			m.SetAttester(fenceTestAttester{generation: 6})
			if err := m.VerifyAndMove(t.Context(), b, "r"); err == nil {
				t.Fatal("cross-class generation accepted")
			}
			if len(f.moved) != 0 || len(f.sealed) != 0 {
				t.Fatal("rejected class candidate changed the last-good receipt")
			}
		})
	}
}

func TestExecFenceEmptyPlanAndStrictPodBothProceed(t *testing.T) {
	m, f, strict := testFenceManager()
	empty := strict
	empty.PodUID, empty.CgroupID, empty.ContainerID = "empty-pod", 41, "empty"
	m.open = func(b sandboxpolicy.Binding) (*FenceCgroups, error) {
		return &FenceCgroups{PodID: b.CgroupID - 1, ContainerID: b.CgroupID}, nil
	}
	// New pods both initially have no pinned row. The fake's singleton row
	// must not appear under the unrelated pod ID in map iteration order.
	kernel := &emptyRowsFence{runtimeFenceFake: f}
	m.kernel = kernel
	candidates := []sandboxpolicy.ExecFenceCandidate{
		{Binding: empty, Plan: fenceTestPlan(api.ModeEnforce), Known: true, NoExec: true},
		{Binding: strict, Plan: fenceTestPlan(api.ModeEnforce), Known: true, Scope: true, MayStrict: true},
	}
	if err := m.Prepare(t.Context(), candidates); err != nil {
		t.Fatal(err)
	}
	if f.publishes != 1 || len(f.members) != 1 || f.members[0].Mode != rf.Strict {
		t.Fatal("empty exec policy marked or strict policy lost")
	}
	if err := m.BeforeReplace(t.Context(), empty, "r"); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyAndMove(t.Context(), empty, "r"); err != nil || len(f.moved) != 0 {
		t.Fatalf("empty policy tried to attest and move an exec mark: %v", err)
	}
}

type emptyRowsFence struct{ *runtimeFenceFake }

func (*emptyRowsFence) ReadPod(uint64) (rf.PodState, bool, error) {
	return rf.PodState{}, false, nil
}

type inheritedFence struct{ *runtimeFenceFake }

func (f inheritedFence) CommitPolicyWithdrawal(p rf.PodRef, c rf.ChildRef) (rf.PodRef, error) {
	if len(f.sealed) == 0 || f.sealed[len(f.sealed)-1] != c {
		return rf.PodRef{}, errors.New("inherited child remains bound")
	}
	return f.runtimeFenceFake.CommitPolicyWithdrawal(p, c)
}

func TestExecFenceReclaimsInheritedHandoffOnAuthoritativeOff(t *testing.T) {
	m, f, b := testFenceManager()
	m.kernel = inheritedFence{f}
	f.state = rf.PodState{PodRef: rf.PodRef{ID: 10, UIDHash: fenceHash("pod"), Revision: 2}, Fallback: rf.Strict, Children: []rf.ChildState{
		{ChildRef: rf.ChildRef{ID: 11, Identity: fenceBindingID(b)}, Mode: rf.Strict, Owner: 77, Generation: 5},
	}}
	if err := m.Prepare(t.Context(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Known: true}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Withdrawn(t.Context(), b); err == nil {
		t.Fatal("Off accepted without exact refence")
	}
	if needed, err := m.PrepareWithdrawal(t.Context(), b); err != nil || !needed {
		t.Fatalf("inherited mark not refenced: %v, %v", needed, err)
	}
	if err := m.Withdrawn(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if needed, err := m.PrepareWithdrawal(t.Context(), b); err != nil || needed {
		t.Fatalf("committed Off not idempotent: %v, %v", needed, err)
	}
}
func TestExecFenceUnknownNeverInventsOff(t *testing.T) {
	m, f, b := testFenceManager()
	if err := m.Prepare(context.Background(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Scope: true, MayStrict: true}}); err != nil {
		t.Fatal(err)
	}
	if len(f.members) != 0 || f.state.Fallback != rf.Strict {
		t.Fatal("unknown classified Off or Audit")
	}
}
func TestExecFenceFailedGenerationRefences(t *testing.T) {
	for _, a := range []fenceTestAttester{{}, {err: errors.New("attestation failed")}} {
		m, f, b := testFenceManager()
		if err := m.Prepare(context.Background(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Plan: fenceTestPlan("enforce"), Known: true, Scope: true}}); err != nil {
			t.Fatal(err)
		}
		m.SetAttester(a)
		if err := m.VerifyAndMove(context.Background(), b, "r"); err == nil {
			t.Fatal("invalid generation accepted")
		}
		if len(f.moved) != 0 || len(f.sealed) != 1 {
			t.Fatal("invalid generation did not refence")
		}
	}
}
func TestExecFenceGlobalArmAndRefusal(t *testing.T) {
	m, f, b := testFenceManager()
	f.err = errors.New("map read failed")
	if err := m.BeforeNativeChange(context.Background(), b); err == nil {
		t.Fatal("read error authorized teardown")
	}
	f.err = nil
	if armed, err := m.ArmAndVerify(); err != nil || !armed {
		t.Fatalf("arm=%v %v", armed, err)
	}
	if err := m.BeforeNativeChange(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	f.snapshot.Retired = true
	if armed, err := m.ArmAndVerify(); err != nil || armed {
		t.Fatalf("retired claimed arm: %v %v", armed, err)
	}
	m.refusal = errors.New("adoption refused")
	if err := m.Prepare(context.Background(), nil); err == nil {
		t.Fatal("sticky refusal ignored")
	}
	if _, err := m.Snapshot(); err == nil {
		t.Fatal("refusal reported status as known")
	}
}
func TestExecFenceScopePreventsDeactivation(t *testing.T) {
	m, _, b := testFenceManager()
	if err := m.Prepare(context.Background(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Plan: fenceTestPlan("audit"), Known: true, Scope: true}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Deactivate(context.Background(), b); err == nil {
		t.Fatal("active scope deactivated")
	}
}

func TestExecFenceUnselectedPodNeedsNoWithdrawalOrMark(t *testing.T) {
	m, f, b := testFenceManager()
	if err := m.Prepare(context.Background(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Known: true}}); err != nil {
		t.Fatal(err)
	}
	if f.publishes != 0 {
		t.Fatal("unselected pod marked")
	}
	if err := m.Withdrawn(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := m.Deactivate(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}
func TestExecFenceInactivePodNotReactivatedWithoutScope(t *testing.T) {
	m, f, b := testFenceManager()
	f.state = rf.PodState{PodRef: rf.PodRef{ID: 10, UIDHash: fenceHash("pod"), Revision: 2}, Inactive: true}
	if err := m.Prepare(context.Background(), []sandboxpolicy.ExecFenceCandidate{{Binding: b, Known: true}}); err != nil {
		t.Fatal(err)
	}
	if f.publishes != 0 {
		t.Fatal("inactive unselected pod reactivated")
	}
}

func TestExecFenceNativeOnlyCustodySurvivesDiscoveryLossWithoutHistory(t *testing.T) {
	m, f, b := testFenceManager()
	candidate := sandboxpolicy.ExecFenceCandidate{Binding: b, Plan: fenceTestPlan(api.ModeEnforce), Known: true, NoExec: true}
	if err := m.Prepare(t.Context(), []sandboxpolicy.ExecFenceCandidate{candidate}); err != nil {
		t.Fatal(err)
	}
	release, err := m.RetainNativeBinding(t.Context(), b, "r")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 256 {
		other := candidate
		other.Binding.ContainerID = fmt.Sprint("unmarked-", i)
		if err := m.Prepare(t.Context(), []sandboxpolicy.ExecFenceCandidate{other}); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.native) != 1 || len(m.unmarked) != 1 || len(m.scope) != 0 || len(m.bindings) != 0 || len(m.pods) != 0 {
		t.Fatal("native-only churn kept historical census records")
	}
	if err := m.BeforeNativeChange(t.Context(), b); err != nil || len(f.sealed) != 0 {
		t.Fatalf("native-only receipt not retained for teardown: %v", err)
	}
	release()
	if err := m.BeforeNativeChange(t.Context(), b); err == nil || len(m.native) != 0 {
		t.Fatal("released custody retained authority")
	}
	if err := m.Prepare(t.Context(), []sandboxpolicy.ExecFenceCandidate{candidate}); err != nil {
		t.Fatal(err)
	}
	newRelease, err := m.RetainNativeBinding(t.Context(), b, "r")
	if err != nil {
		t.Fatal(err)
	}
	release() // delayed duplicate from an old lifetime is not a successor key
	if len(m.native) != 1 {
		t.Fatal("old callback removed successor's custody")
	}
	newRelease()
}

type noRevisionRefenceKernel struct{ *runtimeFenceFake }

func (f noRevisionRefenceKernel) RefenceChild(p rf.PodRef, child rf.ChildRef) (rf.PodRef, error) {
	f.sealed = append(f.sealed, child)
	return p, nil
}

type liveFenceAttest func(context.Context, sandboxpolicy.Binding, string) (uint64, error)

func (a liveFenceAttest) AttestFenceGeneration(ctx context.Context, b sandboxpolicy.Binding, revision string) (uint64, error) {
	return a(ctx, b, revision)
}

func TestExecFenceAttestNeverHoldsManagerLockOrReplaysWitness(t *testing.T) {
	ctx := context.Background()
	m, f, b := testFenceManager()
	m.kernel = noRevisionRefenceKernel{f}
	if err := m.Prepare(ctx, []sandboxpolicy.ExecFenceCandidate{{
		Binding: b, Plan: fenceTestPlan(api.ModeEnforce), Known: true, Scope: true, MayStrict: true,
	}}); err != nil {
		t.Fatal(err)
	}
	m.SetAttester(liveFenceAttest(func(ctx context.Context, binding sandboxpolicy.Binding, _ string) (uint64, error) {
		// The backend holds its record lock by the time it enters this
		// callback. Re-fencing an already-fenced row is an ABI no-op,
		// but must still invalidate a witness across native mutation.
		if err := m.BeforeNativeChange(ctx, binding); err != nil {
			return 0, err
		}
		return 42, nil
	}))
	done := make(chan error, 1)
	go func() { done <- m.VerifyAndMove(ctx, b, "r") }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "changed during native generation attestation") || len(f.moved) != 0 {
			t.Fatalf("stale generation moved after native mutation: %v moved=%v", err, f.moved)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native record lock and manager lock blocked one another")
	}
}

func TestExecFencePrepareExplicitRemovalAllowsPartialAndFullRemovalOnly(t *testing.T) {
	ctx := context.Background()
	m, f, b := testFenceManager()
	m.SetAttester(fenceTestAttester{generation: 11})
	plan := fenceTestPlan(api.ModeEnforce)
	if err := m.Prepare(ctx, []sandboxpolicy.ExecFenceCandidate{{Binding: b, Plan: plan, Known: true, Scope: true, MayStrict: true}}); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyAndMove(ctx, b, plan.Revision); err != nil {
		t.Fatal(err)
	}
	// Unknown binding cannot be authorized for removal.
	other := b
	other.ContainerID = "unknown-cid"
	if err := m.PrepareExplicitRemoval(ctx, other, sandboxpolicy.Plan{}, true); err == nil {
		t.Fatal("unknown binding accepted for explicit removal")
	}
	// Partial removal to Audit must still be refused by BeforeReplace (fixed Strict class).
	auditPlan := fenceTestPlan(api.ModeAudit)
	auditPlan.Revision = "retained-audit"
	if err := m.PrepareExplicitRemoval(ctx, b, auditPlan, false); err != nil {
		t.Fatal(err)
	}
	if err := m.BeforeReplace(ctx, b, auditPlan.Revision); err == nil {
		t.Fatal("cross-class weakening accepted during explicit removal")
	}
	// Partial removal retaining Strict mode succeeds.
	strictPlan := fenceTestPlan(api.ModeEnforce)
	strictPlan.Revision = "retained-strict"
	if err := m.PrepareExplicitRemoval(ctx, b, strictPlan, false); err != nil {
		t.Fatal(err)
	}
	if err := m.BeforeReplace(ctx, b, strictPlan.Revision); err != nil {
		t.Fatalf("same-class partial removal refused: %v", err)
	}
	if err := m.VerifyAndMove(ctx, b, strictPlan.Revision); err != nil {
		t.Fatalf("same-class partial removal failed VerifyAndMove: %v", err)
	}
	// Full removal authorizes PrepareWithdrawal and Withdrawn.
	if err := m.PrepareExplicitRemoval(ctx, b, sandboxpolicy.Plan{}, true); err != nil {
		t.Fatal(err)
	}
	if needed, err := m.PrepareWithdrawal(ctx, b); err != nil || !needed {
		t.Fatalf("explicit full removal PrepareWithdrawal failed: needed=%v err=%v", needed, err)
	}
	if err := m.Withdrawn(ctx, b); err != nil || f.withdrawn != 1 {
		t.Fatalf("explicit full removal Withdrawn failed: err=%v withdrawn=%d", err, f.withdrawn)
	}
}
