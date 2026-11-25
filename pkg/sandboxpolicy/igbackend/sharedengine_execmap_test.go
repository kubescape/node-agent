package igbackend

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// The executable-mapping gate is on for every exec section (V1: no opt-out),
// in the same publish as the policy.
func TestSharedEngineTurnsExecMapGateOn(t *testing.T) {
	f := newSharedFixture(t)
	r, _ := f.backend.Replace(context.Background(), f.binding, singlePlan())
	if !r.Committed || r.ExecMappingsNotEnforceable {
		t.Fatalf("replace %+v", r)
	}
	s := f.node.sessions[0]
	if len(s.inputs) == 0 {
		t.Fatal("nothing compiled")
	}
	for _, in := range s.inputs {
		if !in.ExecMap.Judge || in.ExecMap.DenyAnonymous {
			t.Fatalf("compiled without the gate: %+v", in.ExecMap)
		}
	}
}

// No image index on the node: the publisher refuses the gate before any
// commit. The policy is published again without it, the exec allowlist keeps
// enforcing, and the result says the mappings are not enforceable.
func TestSharedEngineExecMapWithoutImageIndex(t *testing.T) {
	f := newSharedFixture(t)
	f.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(p fullruntime.SharedBindingPolicy) error {
			if p.ExecMap.Judge {
				return fmt.Errorf("publish slot 0: executable-mapping gate: %w: the binding has no sealed image set", fullruntime.ErrSharedImageIndexUnavailable)
			}
			return nil
		}
	}
	r, _ := f.backend.Replace(context.Background(), f.binding, singlePlan())
	if !r.Committed || r.ActiveRevision != "combined-revision" || !r.ExecMappingsNotEnforceable {
		t.Fatalf("replace %+v", r)
	}
	s := f.node.sessions[0]
	last := s.inputs[len(s.inputs)-1]
	if last.ExecMap.Judge || s.route != 10 {
		t.Fatalf("last input %+v, route %d", last.ExecMap, s.route)
	}
	// A revision tries the gate again and falls back again while there is
	// still no index.
	next := singlePlan()
	next.Revision, next.Policies[0].Revision = "next", "policy-next"
	before := len(s.inputs)
	r, _ = f.backend.Replace(context.Background(), f.binding, next)
	if !r.Committed || !r.ExecMappingsNotEnforceable || !s.inputs[before].ExecMap.Judge {
		t.Fatalf("revision %+v, inputs %+v", r, s.inputs[before:])
	}
	// Another refusal is not a reason to drop the gate.
	f2 := newSharedFixture(t)
	f2.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(fullruntime.SharedBindingPolicy) error { return errors.New("boom") }
	}
	if r, err := f2.backend.Replace(context.Background(), f2.binding, singlePlan()); r.Committed || err == nil {
		t.Fatalf("unrelated refusal committed: %+v %v", r, err)
	}
	for _, in := range f2.node.sessions[0].inputs {
		if !in.ExecMap.Judge {
			t.Fatalf("gate dropped on an unrelated refusal: %+v", f2.node.sessions[0].inputs)
		}
	}
}

// A transient kernel refusal (retryable) is tried once more with the gate
// before the fallback.
func TestSharedEngineExecMapRetryableRefusal(t *testing.T) {
	f := newSharedFixture(t)
	refusals := 0
	f.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(p fullruntime.SharedBindingPolicy) error {
			if p.ExecMap.Judge && refusals == 0 {
				refusals++
				return fmt.Errorf("image refused: %w: %w", fullruntime.ErrSharedImageIndexUnavailable, fullruntime.ErrSharedRetryableRefusal)
			}
			return nil
		}
	}
	r, _ := f.backend.Replace(context.Background(), f.binding, singlePlan())
	s := f.node.sessions[0]
	if !r.Committed || r.ExecMappingsNotEnforceable || refusals != 1 || !s.inputs[len(s.inputs)-1].ExecMap.Judge {
		t.Fatalf("replace %+v refusals %d inputs %+v", r, refusals, s.inputs)
	}
}

// A retryable refusal that comes again falls back once; nothing else is
// tried with the gate in that Replace.
func TestSharedEngineExecMapRetryableRefusalTwice(t *testing.T) {
	f := newSharedFixture(t)
	refusals := 0
	f.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(p fullruntime.SharedBindingPolicy) error {
			if p.ExecMap.Judge {
				refusals++
				return fmt.Errorf("image refused: %w: %w", fullruntime.ErrSharedImageIndexUnavailable, fullruntime.ErrSharedRetryableRefusal)
			}
			return nil
		}
	}
	r, _ := f.backend.Replace(context.Background(), f.binding, singlePlan())
	s := f.node.sessions[0]
	if !r.Committed || !r.ExecMappingsNotEnforceable || refusals != 2 || s.inputs[len(s.inputs)-1].ExecMap.Judge {
		t.Fatalf("replace %+v refusals %d inputs %+v", r, refusals, s.inputs)
	}
}

// An outcome-unknown publish never drops the gate, even when its cause is the
// image index: the kernel may have committed, so the work stays pending.
func TestSharedEngineExecMapUnknownOutcomeKeepsGate(t *testing.T) {
	f := newSharedFixture(t)
	f.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(fullruntime.SharedBindingPolicy) error {
			return &fullruntime.ErrSharedPublishUnknown{Err: fmt.Errorf("commit: %w", fullruntime.ErrSharedImageIndexUnavailable)}
		}
	}
	if r, err := f.backend.Replace(context.Background(), f.binding, singlePlan()); r.Committed || err == nil || r.ExecMappingsNotEnforceable {
		t.Fatalf("unknown outcome: %+v %v", r, err)
	}
	for _, in := range f.node.sessions[0].inputs {
		if !in.ExecMap.Judge {
			t.Fatalf("gate dropped on an unknown outcome: %+v", f.node.sessions[0].inputs)
		}
	}
}

// After a fallback, a revision that the gate accepts clears the state.
func TestSharedEngineExecMapGateReturns(t *testing.T) {
	f := newSharedFixture(t)
	index := false
	f.node.onBind = func(s *fakeSharedSession) {
		s.publishErrFor = func(p fullruntime.SharedBindingPolicy) error {
			if p.ExecMap.Judge && !index {
				return fmt.Errorf("%w: no sealed image set", fullruntime.ErrSharedImageIndexUnavailable)
			}
			return nil
		}
	}
	if r, _ := f.backend.Replace(context.Background(), f.binding, singlePlan()); !r.Committed || !r.ExecMappingsNotEnforceable {
		t.Fatalf("fallback %+v", r)
	}
	index = true
	next := singlePlan()
	next.Revision, next.Policies[0].Revision = "next", "policy-next"
	r, _ := f.backend.Replace(context.Background(), f.binding, next)
	s := f.node.sessions[0]
	if !r.Committed || r.ExecMappingsNotEnforceable || !s.inputs[len(s.inputs)-1].ExecMap.Judge {
		t.Fatalf("revision %+v inputs %+v", r, s.inputs)
	}
}

func execMapEvent(scope, route uint64, class, reason uint32) RawFullVerdict {
	return RawFullVerdict{RawVerdict: RawVerdict{Generation: route, Cgroup: 19, Deny: 1, Mode: class, PID: 7, Path: "/tmp/evil.so", PathResult: int32(len("/tmp/evil.so") + 1)}, Shared: true, ExecClass: class, Scope: scope, LoadEpoch: 0x5eed, Mapping: true, Hook: 1, MapReason: reason, Ino: 42, Dev: 0x2a}
}

// A denied (Strict) or would-deny (Audit) mapping is an exec verdict with
// the mapping's hook and reason, attributed only to its binding's scope.
func TestSharedEngineRoutesExecMapVerdicts(t *testing.T) {
	f := newSharedFixture(t)
	if _, err := f.backend.Replace(context.Background(), f.binding, singlePlan()); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatal(err)
	}
	s := f.node.sessions[0]
	f.engine.route(execMapEvent(s.scope, 10, 2, 3))
	audit := execMapEvent(s.scope, 10, 1, 4)
	audit.Deny, audit.Hook, audit.Path, audit.PathResult = 0, 2, "", 0
	f.engine.route(audit)
	f.engine.route(execMapEvent(s.scope+1, 10, 2, 3)) // another binding's scope
	if len(f.receiver.verdicts) != 2 || len(f.errs) != 1 {
		t.Fatalf("verdicts %+v errors %v", f.receiver.verdicts, f.errs)
	}
	v := f.receiver.verdicts[0]
	if v.Verdict != api.ActionDeny || v.WouldDeny || v.Mode != api.RuleEnforce || v.Reason != "mapping_not_from_image" || v.MappingHook != "mmap_file" || v.TargetPath != "/tmp/evil.so" || v.Revision != "combined-revision" || v.LoadEpoch == nil || v.ExecClass == nil || *v.ExecClass != 2 {
		t.Fatalf("strict mapping verdict %+v", v)
	}
	v = f.receiver.verdicts[1]
	if v.Verdict != api.ActionDeny || !v.WouldDeny || v.Mode != api.RuleAudit || v.Reason != "mapping_unknown" || v.MappingHook != "file_mprotect" || v.TargetPath != "" {
		t.Fatalf("audit mapping verdict %+v", v)
	}
}

func TestExecMapVerdictReasons(t *testing.T) {
	for reason, want := range map[uint32]string{3: "mapping_not_from_image", 4: "mapping_unknown", 5: "mapping_anonymous", 6: "mapping_written", 11: "mapping_anonymous", 12: "mapping_anonymous"} {
		if got := execMapReason(reason); got != want {
			t.Errorf("reason %d: %q, want %q", reason, got, want)
		}
	}
	if got := execMapReason(99); got != "mapping_other" {
		t.Errorf("unknown reason: %q", got)
	}
}
