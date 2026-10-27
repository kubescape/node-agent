package igbackend

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type testFullManager struct {
	start  func(context.Context, *api.GadgetInstance, ...gadgetcontext.Option) error
	stop   func(context.Context, string) error
	lookup func(string) *instancemanager.GadgetInstance
}

func (m *testFullManager) StartGadget(ctx context.Context, desired *api.GadgetInstance, opts ...gadgetcontext.Option) error {
	return m.start(ctx, desired, opts...)
}
func (m *testFullManager) StopGadget(ctx context.Context, id string) error { return m.stop(ctx, id) }
func (m *testFullManager) LookupInstance(id string) *instancemanager.GadgetInstance {
	if m.lookup != nil {
		return m.lookup(id)
	}
	return &instancemanager.GadgetInstance{} // Conservative default: still registered.
}

type testFullOwner struct {
	calls                 *[]string
	beforeErr, releaseErr error
	result                fullruntime.PublicationResult
	publicationErr        error
}

func (o *testFullOwner) Activate(context.Context) (fullruntime.PublicationResult, error) {
	*o.calls = append(*o.calls, "activate")
	return o.result, o.publicationErr
}
func (o *testFullOwner) Update(context.Context, *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	*o.calls = append(*o.calls, "update")
	return o.result, o.publicationErr
}
func (o *testFullOwner) AbortPending(context.Context) error {
	*o.calls = append(*o.calls, "abort")
	return o.publicationErr
}
func (o *testFullOwner) Resume(context.Context) (fullruntime.PublicationResult, error) {
	*o.calls = append(*o.calls, "resume")
	return o.result, o.publicationErr
}
func (*testFullOwner) Generation() uint64        { return 3 }
func (*testFullOwner) PendingGeneration() uint64 { return 3 }
func (*testFullOwner) Epochs() map[string]uint64 { return map[string]uint64{"uid": 1} }
func (o *testFullOwner) Check(context.Context) error {
	*o.calls = append(*o.calls, "check")
	return nil
}
func (o *testFullOwner) BeforeStop(context.Context) error {
	*o.calls = append(*o.calls, "drain")
	return o.beforeErr
}
func (o *testFullOwner) ReleaseAfterDetach() error {
	*o.calls = append(*o.calls, "release")
	return o.releaseErr
}

func TestNativeFullStopRetryOrdering(t *testing.T) {
	var calls []string
	owner := &testFullOwner{calls: &calls, beforeErr: context.DeadlineExceeded}
	managerErr := error(context.Canceled)
	manager := &testFullManager{stop: func(context.Context, string) error { calls = append(calls, "stop"); return managerErr }}
	i := &nativeFullInstance{owner: owner, manager: manager, id: "exact", started: true, onRelease: func() { calls = append(calls, "unreserve") }}
	ctx := context.Background()
	if err := i.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(calls, []string{"drain"}) {
		t.Fatalf("failed drain detached resources: %v %v", calls, err)
	}
	if err := i.Check(ctx); err != nil {
		t.Fatal("drain timeout must retain usable owner", err)
	}
	owner.beforeErr = nil
	calls = nil
	if err := i.Stop(ctx); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(calls, []string{"drain", "stop"}) {
		t.Fatalf("canceled join released pins: %v %v", calls, err)
	}
	if i.Detached() {
		t.Fatal("canceled join falsely confirmed detached")
	}
	if err := i.Check(ctx); err == nil {
		t.Fatal("retired owner usable")
	}
	if _, err := i.Activate(ctx); err == nil {
		t.Fatal("retired owner activated")
	}
	if _, err := i.Update(ctx, nil); err == nil {
		t.Fatal("retired owner updated")
	}
	if _, err := i.Resume(ctx); err == nil {
		t.Fatal("retired owner resumed")
	}
	managerErr = instancemanager.ErrNotFound // previous join finished and manager removed its entry
	owner.releaseErr = errors.New("borrowed FD still open")
	calls = nil
	if err := i.Stop(ctx); err == nil || !reflect.DeepEqual(calls, []string{"stop", "release"}) {
		t.Fatalf("failed release discarded ownership: %v %v", calls, err)
	}
	if !i.Detached() {
		t.Fatal("joined teardown lost detached receipt")
	}
	owner.releaseErr = nil
	calls = nil
	if err := i.Stop(ctx); err != nil || !reflect.DeepEqual(calls, []string{"release", "unreserve"}) {
		t.Fatalf("release retry: %v %v", calls, err)
	}
	calls = nil
	if err := i.Stop(ctx); err != nil || len(calls) != 0 {
		t.Fatalf("stop not idempotent: %v %v", calls, err)
	}
}

func TestNativeFullPublicationResultPreserved(t *testing.T) {
	var calls []string
	failure := errors.New("postcommit finalization failed")
	owner := &testFullOwner{calls: &calls, result: fullruntime.PublicationResult{Committed: true, Generation: 3}, publicationErr: failure}
	i := &nativeFullInstance{owner: owner, started: true}
	ctx := context.Background()
	for _, invoke := range []func() (fullruntime.PublicationResult, error){func() (fullruntime.PublicationResult, error) { return i.Activate(ctx) }, func() (fullruntime.PublicationResult, error) { return i.Update(ctx, nil) }, func() (fullruntime.PublicationResult, error) { return i.Resume(ctx) }} {
		result, err := invoke()
		if !errors.Is(err, failure) || result != owner.result {
			t.Fatalf("lost partial commit: %+v %v", result, err)
		}
	}
	if !reflect.DeepEqual(calls, []string{"activate", "update", "resume"}) || i.Generation() != 3 || i.PendingGeneration() != 3 || i.Epochs()["uid"] != 1 {
		t.Fatalf("wrong owner delegation: %v", calls)
	}
	i.started = false
	if _, err := i.Activate(ctx); err == nil {
		t.Fatal("failed startup activated")
	}
}

func TestNativeFullFailedStartRetainsOwnerAndID(t *testing.T) {
	budget, err := fullruntime.NewBudget(fullruntime.BudgetLimits{Owners: 1, MapPayloadBytes: fullruntime.OwnerMapPayloadLimit, ProgramInstructions: fullruntime.OwnerInstructionLimit, HistoryEntries: fullruntime.OwnerHistoryLimit})
	if err != nil {
		t.Fatal(err)
	}
	startupErr := errors.New("late startup failure")
	starts, stops, acquires := 0, 0, 0
	manager := &testFullManager{start: func(ctx context.Context, desired *api.GadgetInstance, options ...gadgetcontext.Option) error {
		starts++
		if desired.Id != "binding" || desired.GadgetConfig.ImageName != "trusted-owner" || len(options) != 3 {
			t.Fatalf("bad desired instance: %+v", desired)
		}
		return startupErr
	}, stop: func(context.Context, string) error { stops++; return instancemanager.ErrNotFound }}
	engine := &nativeFullEngine{manager: manager, image: "trusted-owner", controlRoot: "/sys/fs/cgroup", budget: budget, instances: make(map[string]*nativeFullInstance)}
	binding := sandboxpolicy.Binding{ContainerName: "app", PID: 42, CgroupID: 91}
	program, err := CompileFull(binding, verdictPlan(), 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := FullStartConfig{Binding: binding, Program: program, Acquire: func(context.Context) (fullruntime.BindingLease, error) {
		acquires++
		return nil, errors.New("must not acquire outside operator start")
	}}
	instance, err := engine.Start(context.Background(), "binding", config, nil)
	if instance == nil || !errors.Is(err, startupErr) || budget.Usage().Owners != 1 || acquires != 0 {
		t.Fatalf("lost failed candidate: %v %v %+v", instance, err, budget.Usage())
	}
	if _, err = instance.Activate(context.Background()); err == nil {
		t.Fatal("failed manager start activated")
	}
	if second, err := engine.Start(context.Background(), "binding", config, nil); err == nil || second != nil || starts != 1 {
		t.Fatal("duplicate ID disturbed existing owner")
	}
	if err = instance.Stop(context.Background()); err != nil || budget.Usage().Owners != 0 || stops != 1 || len(engine.instances) != 0 {
		t.Fatalf("cleanup failed: %v %+v", err, budget.Usage())
	}
	// Reusing a released ID gets a fresh owner, not the previous stopped handle.
	second, err := engine.Start(context.Background(), "binding", config, nil)
	if second == nil || second == instance || !errors.Is(err, startupErr) || starts != 2 {
		t.Fatal("released ID not reusable", err)
	}
	if err = second.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFullConstructorRequiresTrustedConfiguration(t *testing.T) {
	if _, err := NewNativeFullEngine(nil, nil, nil, "", "", nil, nil); err == nil {
		t.Fatal("accepted incomplete native runtime configuration")
	}
}

func TestNativeFullVerdictSubscription(t *testing.T) {
	if err := subscribeFullVerdicts(nil, nil, nil); err == nil {
		t.Fatal("accepted missing datasource")
	}
	missing, _ := datasource.New(datasource.TypeSingle, "verdict")
	if err := subscribeFullVerdicts(missing, nil, nil); err == nil {
		t.Fatal("accepted missing fields")
	}
	ds, err := datasource.New(datasource.TypeSingle, "verdict")
	if err != nil {
		t.Fatal(err)
	}
	for name, kind := range map[string]api.Kind{"generation": api.Kind_Uint64, "cgroup": api.Kind_Uint64, "deny": api.Kind_Uint32, "mode": api.Kind_Uint32, "path_result": api.Kind_Int32, "host_pid": api.Kind_Uint32, "path": api.Kind_CString, "matched_rules": api.ArrayOf(api.Kind_Uint64), "error": api.Kind_Uint32} {
		if _, err = ds.AddField(name, kind); err != nil {
			t.Fatal(err)
		}
	}
	var got []RawFullVerdict
	errorsSeen := 0
	if err = subscribeFullVerdicts(ds, func(r RawFullVerdict) { got = append(got, r) }, func(error) { errorsSeen++ }); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{32, 31} {
		packet, err := ds.NewPacketSingle()
		if err != nil {
			t.Fatal(err)
		}
		ds.GetField("generation").PutUint64(packet, 7)
		ds.GetField("cgroup").PutUint64(packet, 91)
		ds.GetField("mode").PutUint32(packet, 2)
		ds.GetField("deny").PutUint32(packet, 0)
		ds.GetField("error").PutUint32(packet, 0)
		ds.GetField("host_pid").PutUint32(packet, 42)
		ds.GetField("path_result").PutInt32(packet, -1)
		ds.GetField("path").PutString(packet, "")
		bits := make([]byte, size)
		ds.ByteOrder().PutUint64(bits, 1)
		if err = ds.GetField("matched_rules").Set(packet, bits); err != nil {
			t.Fatal(err)
		}
		if err = ds.EmitAndRelease(packet); err != nil {
			t.Fatal("telemetry error escaped into runtime", err)
		}
	}
	if len(got) != 1 || got[0].Generation != 7 || got[0].MatchedRules[0] != 1 || errorsSeen != 1 {
		t.Fatalf("wrong decoded/drop callbacks: %+v errors=%d", got, errorsSeen)
	}
}

func TestNativeFullRejectsWrongVerdictSchemaBeforeActivation(t *testing.T) {
	for _, bad := range []string{"generation", "matched_rules", "path", "error"} {
		ds, err := datasource.New(datasource.TypeSingle, "verdict")
		if err != nil {
			t.Fatal(err)
		}
		for name, kind := range map[string]api.Kind{"generation": api.Kind_Uint64, "cgroup": api.Kind_Uint64, "deny": api.Kind_Uint32, "mode": api.Kind_Uint32, "path_result": api.Kind_Int32, "host_pid": api.Kind_Uint32, "path": api.Kind_CString, "matched_rules": api.ArrayOf(api.Kind_Uint64), "error": api.Kind_Uint32} {
			if name == bad {
				kind = api.Kind_Bytes
			}
			if _, err = ds.AddField(name, kind); err != nil {
				t.Fatal(err)
			}
		}
		if err = subscribeFullVerdicts(ds, nil, nil); err == nil {
			t.Fatalf("accepted wrong type for %s", bad)
		}
	}
}

func TestNativeFullTerminalStopErrorPreservesDetachedReceipt(t *testing.T) {
	for _, releaseFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "released", true: "release-retry"}[releaseFails], func(t *testing.T) {
			var calls []string
			terminal := errors.New("terminal gadget Run error")
			releaseErr := errors.New("pinned resource release error")
			owner := &testFullOwner{calls: &calls}
			if releaseFails {
				owner.releaseErr = releaseErr
			}
			manager := &testFullManager{stop: func(context.Context, string) error { calls = append(calls, "stop"); return terminal }, lookup: func(id string) *instancemanager.GadgetInstance {
				if id != "exact" {
					t.Fatalf("looked up wrong ID %q", id)
				}
				calls = append(calls, "lookup-absent")
				return nil
			}}
			i := &nativeFullInstance{owner: owner, manager: manager, id: "exact", started: true, onRelease: func() { calls = append(calls, "unreserve") }}
			err := i.Stop(context.Background())
			if !errors.Is(err, terminal) || !i.Detached() {
				t.Fatalf("lost terminal error or joined receipt: detached=%v err=%v", i.Detached(), err)
			}
			want := []string{"drain", "stop", "lookup-absent", "release"}
			if !releaseFails {
				want = append(want, "unreserve")
			}
			if !reflect.DeepEqual(calls, want) || errors.Is(err, releaseErr) != releaseFails {
				t.Fatalf("wrong release behavior: %v err=%v", calls, err)
			}
			calls = nil
			owner.releaseErr = nil
			if err = i.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			want = nil
			if releaseFails {
				want = []string{"release", "unreserve"}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("retry re-detached joined instance: %v", calls)
			}
		})
	}
}

func TestNativeFullAbortPendingDelegatesOnlyWhileUsable(t *testing.T) {
	var calls []string
	failure := errors.New("abort failed")
	owner := &testFullOwner{calls: &calls, publicationErr: failure}
	i := &nativeFullInstance{owner: owner, started: true}
	if err := i.AbortPending(t.Context()); !errors.Is(err, failure) || !reflect.DeepEqual(calls, []string{"abort"}) {
		t.Fatalf("abort delegation: %v %v", calls, err)
	}
	for _, state := range []string{"not-started", "retired", "released"} {
		t.Run(state, func(t *testing.T) {
			i.started, i.retired, i.released = state != "not-started", state == "retired", state == "released"
			calls = nil
			if err := i.AbortPending(t.Context()); err == nil || len(calls) != 0 {
				t.Fatalf("unusable owner abort: %v %v", calls, err)
			}
		})
	}
}
