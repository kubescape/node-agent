package igbackend

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

var failure = errors.New("injected failure")

type fakeLease struct {
	checkErr error
	closed   int
}

func (l *fakeLease) Check() error { return l.checkErr }
func (l *fakeLease) Close() error { l.closed++; return nil }

type fakeValidator struct {
	leases    []*fakeLease
	err       error
	nextCheck error
}

func (v *fakeValidator) Acquire(context.Context, sandboxpolicy.Binding) (Lease, error) {
	if v.err != nil {
		return nil, v.err
	}
	l := &fakeLease{checkErr: v.nextCheck}
	v.leases = append(v.leases, l)
	return l, nil
}

type fakeInstance struct {
	readyErr, stopErr, unbindErr error
	stops, unbound               int
}

func (i *fakeInstance) Ready() error               { return i.readyErr }
func (i *fakeInstance) Stop(context.Context) error { i.stops++; return i.stopErr }
func (i *fakeInstance) Unbind(context.Context, execruntime.ContainerIdentity) error {
	i.unbound++
	return i.unbindErr
}

type fakeEngine struct {
	instances                 []*fakeInstance
	configs                   []execruntime.Config
	startErr, errorAfterStart error
	emit                      func(RawVerdict)
}

func (e *fakeEngine) Start(_ context.Context, _ string, c execruntime.Config, emit func(RawVerdict)) (Instance, error) {
	if e.startErr != nil {
		return nil, e.startErr
	}
	i := &fakeInstance{readyErr: e.errorAfterStart}
	e.instances = append(e.instances, i)
	e.configs = append(e.configs, c)
	e.emit = emit
	return i, nil
}
func fixture(t *testing.T) (*Backend, *fakeEngine, *fakeValidator, sandboxpolicy.Binding, sandboxpolicy.Plan) {
	t.Helper()
	e, v := &fakeEngine{}, &fakeValidator{}
	b, err := New(e, v, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "full-container-id", CgroupID: 42, CgroupPath: "/kubepods/target", PID: 123, MountNamespace: 456}
	plan := sandboxpolicy.Plan{Revision: "one", Policies: []sandboxpolicy.CompiledPolicy{{Mode: api.ModeEnforce, RootRole: "agent", Exec: api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{{Rule: api.Rule{Name: "allow-tool", Action: api.ActionAllow, Origin: "test"}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/tool"}}}}}}}}}
	return b, e, v, binding, plan
}
func TestReplaceCommitAndCleanupRetry(t *testing.T) {
	b, e, v, binding, p := fixture(t)
	ctx := context.Background()
	first, err := b.Replace(ctx, binding, p)
	if err != nil || !first.Committed {
		t.Fatal(first, err)
	}
	if len(e.configs[0].Targets) != 0 || len(e.configs[0].InitialBindings) != 1 {
		t.Fatal("not exact initial binding")
	}
	e.startErr = failure
	p.Revision = "two"
	failed, err := b.Replace(ctx, binding, p)
	if !errors.Is(err, failure) || failed.Committed || e.instances[0].stops != 0 {
		t.Fatal(failed, err)
	}
	e.startErr = nil
	e.instances[0].stopErr = failure
	next, err := b.Replace(ctx, binding, p)
	if !errors.Is(err, failure) || !next.Committed || next.ActiveRevision != "two" {
		t.Fatal(next, err)
	}
	if v.leases[0].closed != 0 {
		t.Fatal("released identity before links stopped")
	}
	again, err := b.Replace(ctx, binding, p)
	if !again.Committed || err == nil || len(e.instances) != 2 {
		t.Fatal("same revision restarted")
	}
	e.instances[0].stopErr = nil
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 2 || v.leases[0].closed != 1 {
		t.Fatal("cleanup did not finish without restart")
	}
}
func TestWithdrawalCommitAndStaleIdentity(t *testing.T) {
	b, e, _, binding, p := fixture(t)
	ctx := context.Background()
	b.Replace(ctx, binding, p)
	stale := binding
	stale.ContainerID = "stale"
	if r, err := b.Withdraw(ctx, stale); err != nil || !r.Committed || e.instances[0].unbound != 0 {
		t.Fatal(r, err)
	}
	e.instances[0].unbindErr = failure
	if r, err := b.Withdraw(ctx, binding); err == nil || r.Committed {
		t.Fatal(r, err)
	}
	e.instances[0].unbindErr = nil
	e.instances[0].stopErr = failure
	if r, err := b.Withdraw(ctx, binding); err == nil || !r.Committed {
		t.Fatal(r, err)
	}
	if r, err := b.Replace(ctx, binding, p); err == nil || r.Committed {
		t.Fatal("reinstalled while cleanup pending", r, err)
	}
	e.instances[0].stopErr = nil
	if r, err := b.Withdraw(ctx, binding); err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	if r, err := b.Replace(ctx, stale, p); err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	if r, err := b.Withdraw(ctx, binding); err != nil || !r.Committed || e.instances[1].unbound != 0 {
		t.Fatal("old deletion touched new identity", r, err)
	}
}
func TestIdentityAndReadinessFailure(t *testing.T) {
	b, e, v, binding, p := fixture(t)
	ctx := context.Background()
	v.err = failure
	if r, err := b.Replace(ctx, binding, p); err == nil || r.Committed || len(e.instances) != 0 {
		t.Fatal(r, err)
	}
	v.err = nil
	v.nextCheck = failure
	if r, err := b.Replace(ctx, binding, p); err == nil || r.Committed || e.instances[0].stops != 1 || v.leases[0].closed != 1 {
		t.Fatal(r, err)
	}
	v.nextCheck = nil
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	changed := binding
	changed.PID++
	if r, err := b.Replace(ctx, changed, p); err == nil || r.Committed {
		t.Fatal("cgroup reused without retiring old identity")
	}
	e.instances[1].readyErr = failure
	if r, err := b.Replace(ctx, binding, p); err == nil || !r.Committed {
		t.Fatal("lost readiness not reported", r, err)
	}
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := b.Replace(ctx, binding, p); err == nil || r.Committed {
		t.Fatal("closed backend restarted")
	}
}
func TestCompileRejectsNonrepresentableSemantics(t *testing.T) {
	_, _, _, binding, p := fixture(t)
	cases := map[string]func(*sandboxpolicy.Plan){
		"multiple":        func(p *sandboxpolicy.Plan) { p.Policies = append(p.Policies, p.Policies[0]) },
		"root-role":       func(p *sandboxpolicy.Plan) { p.Policies[0].RootRole = "admin" },
		"off":             func(p *sandboxpolicy.Plan) { p.Policies[0].Mode = api.ModeOff },
		"missing-default": func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Default = "" },
		"actor":           func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Actor = &api.Actor{} },
		"class":           func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.PathClass = []string{"unresolved"} },
		"from-image":      func(p *sandboxpolicy.Plan) { f := false; p.Policies[0].Exec.Rules[0].Target.FromImage = &f },
		"fstype":          func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.FSType = []string{"overlay"} },
		"argv":            func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.Argv = &api.ArgvPredicate{} },
		"role":            func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.SetRole = "admin" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, fresh := fixture(t)
			mutate(&fresh)
			if _, err := Compile(binding, fresh, 1); err == nil {
				t.Fatal("silently weakened policy")
			}
		})
	}
	if _, err := Compile(binding, p, 1); err != nil {
		t.Fatal(err)
	}
}
func TestVerdictAttribution(t *testing.T) {
	_, _, _, binding, p := fixture(t)
	r := RawVerdict{Generation: 1, Cgroup: binding.CgroupID, Mode: 2, PathResult: 10, Path: "/bin/tool", PID: 12}
	got, err := DecodeVerdict(binding, p, 1, r)
	if err != nil || got.Rule != "allow-tool" || got.Origin != "test" || got.UID != nil || got.Argv != nil {
		t.Fatal(got, err)
	}
	p.Policies[0].Exec.Rules = append(p.Policies[0].Exec.Rules, p.Policies[0].Exec.Rules[0])
	got, err = DecodeVerdict(binding, p, 1, r)
	if err != nil || got.Rule != "" || got.Origin != "" {
		t.Fatal("ambiguous attribution fabricated", got, err)
	}
	r.Generation = 2
	if _, err := DecodeVerdict(binding, p, 1, r); err == nil {
		t.Fatal("stale event accepted")
	}
	r.Generation = 1
	r.PathResult = -1
	r.Deny = 1
	r.Mode = 1
	got, err = DecodeVerdict(binding, p, 1, r)
	if err != nil || got.TargetPath != "" || !got.WouldDeny || got.Reason != "path_resolution_error" {
		t.Fatal(got, err)
	}
}

type receiverFunc func(context.Context, sandboxpolicy.Verdict) error

func (f receiverFunc) ReportVerdict(ctx context.Context, v sandboxpolicy.Verdict) error {
	return f(ctx, v)
}
func TestExporterFailureDoesNotAffectEnforcement(t *testing.T) {
	b, e, _, binding, p := fixture(t)
	calls, reports := 0, 0
	b.receiver = receiverFunc(func(_ context.Context, v sandboxpolicy.Verdict) error {
		calls++
		if v.Rule != "allow-tool" {
			t.Error("callback plan mutated")
		}
		return failure
	})
	b.onError = func(err error) {
		if errors.Is(err, failure) {
			reports++
		}
	}
	if _, err := b.Replace(context.Background(), binding, p); err != nil {
		t.Fatal(err)
	}
	p.Policies[0].Exec.Rules[0].Name = "mutated"
	e.emit(RawVerdict{Generation: e.configs[0].Entries[0].Generation, Cgroup: binding.CgroupID, Mode: 2, PathResult: 10, Path: "/bin/tool"})
	if calls != 1 || reports != 1 || e.instances[0].stops != 0 || e.instances[0].unbound != 0 {
		t.Fatal("export failure changed enforcement")
	}
}

func TestOwnedIdentityCapacityIncludesRetiringRecords(t *testing.T) {
	b, e, v, base, p := fixture(t)
	ctx := context.Background()
	bindingAt := func(i int) sandboxpolicy.Binding {
		binding := base
		binding.ContainerID = fmt.Sprintf("container-%d", i)
		binding.CgroupID = uint64(i + 1)
		binding.CgroupPath = fmt.Sprintf("/containers/%d", i)
		return binding
	}
	for i := 0; i < execpolicy.KernelMaxBindings; i++ {
		instance := &fakeInstance{}
		owner := &owned{instance: instance, lease: &fakeLease{}}
		state := &record{binding: bindingAt(i), revision: "old"}
		if i%2 == 0 {
			state.retiring = []*owned{owner}
			instance.stopErr = failure
		} else {
			state.active = owner
		}
		b.records[key(bindingAt(i))] = state
	}
	// Empty historical records do not consume capacity and are also reclaimed.
	b.records[key(bindingAt(execpolicy.KernelMaxBindings+10))] = &record{}
	rejected := bindingAt(execpolicy.KernelMaxBindings)
	result, err := b.Replace(ctx, rejected, p)
	if err == nil || !strings.Contains(err.Error(), "capacity") || result.Committed || len(e.instances) != 0 || len(v.leases) != 0 || b.sequence != 0 {
		t.Fatal("capacity failure prepared a partial candidate", result, err)
	}
	if len(b.records) != execpolicy.KernelMaxBindings {
		t.Fatal("empty record retained")
	}
	// An existing identity can be replaced without requiring an extra identity slot.
	if result, err := b.Replace(ctx, bindingAt(1), p); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if len(b.records) != execpolicy.KernelMaxBindings || len(e.instances) != 1 {
		t.Fatal("replacement changed identity count")
	}
	// Pending retired-instance cleanup must continue to occupy its identity slot.
	if result, err := b.Withdraw(ctx, bindingAt(0)); err == nil || result.Committed {
		t.Fatal(result, err)
	}
	if _, err := b.Replace(ctx, rejected, p); err == nil {
		t.Fatal("retiring-only identity was not counted")
	}
	retired := b.records[key(bindingAt(0))].retiring[0].instance.(*fakeInstance)
	retired.stopErr = nil
	if result, err := b.Withdraw(ctx, bindingAt(0)); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if result, err := b.Replace(ctx, rejected, p); err != nil || !result.Committed {
		t.Fatal("released slot was not reusable", result, err)
	}
	if len(b.records) != execpolicy.KernelMaxBindings {
		t.Fatal("wrong owned count")
	}
}

func TestGenerationExhaustionNeverWraps(t *testing.T) {
	b, e, v, binding, p := fixture(t)
	ctx := context.Background()
	b.sequence = math.MaxUint64 - 1
	if result, err := b.Replace(ctx, binding, p); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if e.configs[0].Entries[0].Generation != math.MaxUint64 {
		t.Fatal("last generation not used exactly once")
	}
	// Rechecking an already committed generation needs no new generation.
	if result, err := b.Replace(ctx, binding, p); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	p.Revision = "next"
	for i := 0; i < 3; i++ {
		result, err := b.Replace(ctx, binding, p)
		if err == nil || !strings.Contains(err.Error(), "exhausted") || result.Committed || b.sequence != math.MaxUint64 {
			t.Fatal("generation exhaustion was not sticky", result, err)
		}
	}
	if len(e.instances) != 1 || len(v.leases) != 1 || e.instances[0].stops != 0 {
		t.Fatal("exhaustion touched the last-good instance")
	}
}

func TestFailedLastGenerationIsNotReused(t *testing.T) {
	b, e, v, binding, p := fixture(t)
	b.sequence = math.MaxUint64 - 1
	e.startErr = failure
	if result, err := b.Replace(context.Background(), binding, p); !errors.Is(err, failure) || result.Committed {
		t.Fatal(result, err)
	}
	e.startErr = nil
	for i := 0; i < 2; i++ {
		if result, err := b.Replace(context.Background(), binding, p); err == nil || result.Committed || b.sequence != math.MaxUint64 {
			t.Fatal(result, err)
		}
	}
	if len(v.leases) != 1 || v.leases[0].closed != 1 || len(b.records) != 0 || len(e.instances) != 0 {
		t.Fatal("failed final generation was retried")
	}
}

func TestFailedCandidateChurnReclaimsEmptyRecords(t *testing.T) {
	b, e, _, binding, p := fixture(t)
	e.errorAfterStart = failure
	for i := 0; i < execpolicy.KernelMaxBindings+1; i++ {
		binding.ContainerID = fmt.Sprintf("rejected-%d", i)
		binding.CgroupID = uint64(i + 1)
		result, err := b.Replace(context.Background(), binding, p)
		if !errors.Is(err, failure) || result.Committed {
			t.Fatal(result, err)
		}
		if len(b.records) != 0 {
			t.Fatalf("failed candidate %d leaked a record", i)
		}
	}
}

func TestExistingProtectionHealthIsDistinctFromCleanupOwnership(t *testing.T) {
	for _, test := range []struct {
		name    string
		lose    func(*fakeEngine, *fakeValidator)
		invalid bool
	}{{"stopped", func(e *fakeEngine, _ *fakeValidator) { e.instances[0].readyErr = failure }, false}, {"lease lost", func(_ *fakeEngine, v *fakeValidator) { v.leases[0].checkErr = failure }, false}, {"invalid candidate with lost owner", func(e *fakeEngine, _ *fakeValidator) { e.instances[0].readyErr = failure }, true}} {
		t.Run(test.name, func(t *testing.T) {
			b, e, v, binding, p := fixture(t)
			ctx := context.Background()
			if _, err := b.Replace(ctx, binding, p); err != nil {
				t.Fatal(err)
			}
			test.lose(e, v)
			if test.invalid {
				p.Revision = "invalid"
				p.Policies[0].RootRole = "unsupported"
			}
			result, err := b.Replace(ctx, binding, p)
			if err == nil || !result.ProtectionUnconfirmed || b.records[key(binding)].active == nil {
				t.Fatalf("lost protection treated as healthy ownership: %+v %v", result, err)
			}
			if test.invalid && result.Committed {
				t.Fatal("invalid candidate reported committed")
			}
			if len(e.instances) != 1 {
				t.Fatal("health check started a replacement")
			}
		})
	}
}

func TestHealthyRollbackCleanupAndRecoveryStayConfirmed(t *testing.T) {
	b, e, v, binding, p := fixture(t)
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	invalid := p
	invalid.Revision = "invalid"
	invalid.Policies = append([]sandboxpolicy.CompiledPolicy(nil), p.Policies...)
	invalid.Policies[0].RootRole = "unsupported"
	result, err := b.Replace(ctx, binding, invalid)
	if err == nil || result.Committed || result.ProtectionUnconfirmed {
		t.Fatalf("healthy rollback marked lost: %+v %v", result, err)
	}
	e.instances[0].readyErr = failure
	result, err = b.Replace(ctx, binding, p)
	if err == nil || !result.ProtectionUnconfirmed {
		t.Fatal("external loss not detected")
	}
	e.instances[0].readyErr = nil
	result, err = b.Replace(ctx, binding, p)
	if err != nil || result.ProtectionUnconfirmed || !result.Committed {
		t.Fatal("successful re-attestation did not clear uncertainty")
	}
	v.leases[0].checkErr = failure
	e.instances[0].stopErr = failure
	p.Revision = "replacement"
	result, err = b.Replace(ctx, binding, p)
	if err == nil || !result.Committed || result.ProtectionUnconfirmed || result.ActiveRevision != "replacement" {
		t.Fatalf("healthy new committed instance confused with lost old owner: %+v %v", result, err)
	}
	if len(e.instances) != 2 {
		t.Fatal("replacement not started")
	}
	e.instances[0].stopErr = nil
	result, err = b.Replace(ctx, binding, p)
	if err != nil || result.ProtectionUnconfirmed || !result.Committed {
		t.Fatal("cleanup/recovery did not converge")
	}
}

func TestChangedRuntimeIdentityDoesNotHideLostPriorOwner(t *testing.T) {
	b, _, v, binding, p := fixture(t)
	ctx := context.Background()
	if _, err := b.Replace(ctx, binding, p); err != nil {
		t.Fatal(err)
	}
	v.leases[0].checkErr = failure
	replacement := binding
	replacement.PID++
	result, err := b.Replace(ctx, replacement, p)
	if err == nil || result.Committed || !result.ProtectionUnconfirmed || b.records[key(binding)].active == nil {
		t.Fatalf("identity conflict hid lost prior protection: %+v %v", result, err)
	}
}

func TestWithdrawalFailureChecksRetainedProtection(t *testing.T) {
	for _, stage := range []string{"cleanup", "unbind"} {
		for _, health := range []string{"healthy", "not-ready", "lease-lost"} {
			t.Run(stage+"/"+health, func(t *testing.T) {
				b, e, v, binding, plan := fixture(t)
				ctx := context.Background()
				if _, err := b.Replace(ctx, binding, plan); err != nil {
					t.Fatal(err)
				}
				active, lease := e.instances[0], v.leases[0]
				operationErr := errors.New("withdrawal failed")
				healthErr := errors.New("retained protection lost")
				if stage == "cleanup" {
					retired := &fakeInstance{stopErr: operationErr, readyErr: healthErr}
					b.records[key(binding)].retiring = []*owned{{instance: retired, lease: &fakeLease{}}}
				} else {
					active.unbindErr = operationErr
				}
				if health == "not-ready" {
					active.readyErr = healthErr
				}
				if health == "lease-lost" {
					lease.checkErr = healthErr
				}
				result, err := b.Withdraw(ctx, binding)
				if result.Committed || result.ProtectionUnconfirmed != (health != "healthy") || !errors.Is(err, operationErr) {
					t.Fatalf("wrong withdrawal result: %+v %v", result, err)
				}
				if health != "healthy" && !errors.Is(err, healthErr) {
					t.Fatalf("health failure missing: %v", err)
				}
				if b.records[key(binding)].active == nil || lease.closed != 0 {
					t.Fatal("failed withdrawal lost retained owner")
				}
			})
		}
	}
}

func TestWithdrawalRetiringOnlyDoesNotClaimProtection(t *testing.T) {
	b, _, _, binding, _ := fixture(t)
	b.records[key(binding)] = &record{binding: binding, retiring: []*owned{{instance: &fakeInstance{stopErr: failure}, lease: &fakeLease{}}}}
	result, err := b.Withdraw(context.Background(), binding)
	if result.Committed || !result.ProtectionUnconfirmed || !errors.Is(err, failure) {
		t.Fatalf("retiring ownership reported as confirmed protection: %+v %v", result, err)
	}
}

func TestLegacyBindingMetadataCannotReuseOrWithdrawOwner(t *testing.T) {
	for name, mutate := range map[string]func(*sandboxpolicy.Binding){
		"pod UID":        func(b *sandboxpolicy.Binding) { b.PodUID = "stale-uid" },
		"namespace":      func(b *sandboxpolicy.Binding) { b.Namespace = "other-ns" },
		"pod name":       func(b *sandboxpolicy.Binding) { b.PodName = "other-pod" },
		"container name": func(b *sandboxpolicy.Binding) { b.ContainerName = "other-container" },
		"kind":           func(b *sandboxpolicy.Binding) { b.Kind = "init" },
	} {
		t.Run(name, func(t *testing.T) {
			b, e, v, binding, plan := fixture(t)
			binding.PodUID, binding.Namespace, binding.PodName, binding.ContainerName, binding.Kind = "current-uid", "ns", "pod", "app", "regular"
			ctx := context.Background()
			if _, err := b.Replace(ctx, binding, plan); err != nil {
				t.Fatal(err)
			}
			retired := &fakeInstance{}
			b.records[key(binding)].retiring = []*owned{{instance: retired, lease: &fakeLease{}}}
			stale := binding
			mutate(&stale)
			for _, revision := range []string{plan.Revision, "next"} {
				candidate := plan
				candidate.Revision = revision
				result, err := b.Replace(ctx, stale, candidate)
				if err == nil || result.Committed {
					t.Fatalf("contradictory metadata reused owner: %+v %v", result, err)
				}
			}
			result, err := b.Withdraw(ctx, stale)
			if err != nil || !result.Committed {
				t.Fatalf("stale withdrawal not ignored: %+v %v", result, err)
			}
			if len(e.instances) != 1 || e.instances[0].stops != 0 || e.instances[0].unbound != 0 || v.leases[0].closed != 0 || retired.stops != 0 {
				t.Fatal("stale metadata mutated the current owner")
			}
			if err := b.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if e.instances[0].unbound != 1 || e.instances[0].stops != 1 || v.leases[0].closed != 1 || len(b.records) != 0 {
				t.Fatal("Close lost authoritative binding metadata")
			}
		})
	}
}

func TestLegacyStalePodWithdrawalPreservesOwner(t *testing.T) {
	b, e, v, binding, plan := fixture(t)
	binding.PodUID = "current"
	if _, err := b.Replace(context.Background(), binding, plan); err != nil {
		t.Fatal(err)
	}
	stale := binding
	stale.PodUID = "old"
	result, err := b.Withdraw(context.Background(), stale)
	if err != nil || !result.Committed || e.instances[0].unbound != 0 || e.instances[0].stops != 0 || v.leases[0].closed != 0 || len(b.records) != 1 {
		t.Fatalf("stale pod withdrew live protection: %+v %v", result, err)
	}
}
