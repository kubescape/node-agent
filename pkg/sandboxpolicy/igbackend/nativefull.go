package igbackend

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"oras.land/oras-go/v2"
)

// NewNativeFullEngine borrows the initialized runtime and trusted OCI archive.
// The caller must stop every instance before closing the runtime. The one shared
// budget must cover all engines that could target the same cgroup. No fallback to
// immutable/path-only enforcement occurs when the persistent image is unsupported.
func NewNativeFullEngine(rt runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, image, controlRoot string, budget *fullruntime.Budget, onError func(error)) (FullEngine, error) {
	if rt == nil || kube == nil || store == nil || image == "" || budget == nil || !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot {
		return nil, fmt.Errorf("runtime, Kubernetes operator, trusted OCI image/store, canonical control root and shared budget are required")
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	return &nativeFullEngine{manager: manager, kube: kube, store: store, image: image, controlRoot: controlRoot, budget: budget, onError: onError, instances: make(map[string]*nativeFullInstance)}, nil
}

type fullManager interface {
	StartGadget(context.Context, *api.GadgetInstance, ...gadgetcontext.Option) error
	StopGadget(context.Context, string) error
	LookupInstance(string) *instancemanager.GadgetInstance
}

type fullOwner interface {
	AbortPending(context.Context) error
	Activate(context.Context) (fullruntime.PublicationResult, error)
	Update(context.Context, *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error)
	Resume(context.Context) (fullruntime.PublicationResult, error)
	Generation() uint64
	PendingGeneration() uint64
	Epochs() map[string]uint64
	Check(context.Context) error
	BeforeStop(context.Context) error
	ReleaseAfterDetach() error
}

type nativeFullEngine struct {
	mu          sync.Mutex
	manager     fullManager
	kube        operators.DataOperator
	store       oras.ReadOnlyTarget
	image       string
	controlRoot string
	budget      *fullruntime.Budget
	onError     func(error)
	instances   map[string]*nativeFullInstance
}

type nativeFullInstance struct {
	mu        sync.Mutex
	owner     fullOwner
	manager   fullManager
	id        string
	started   bool
	retired   bool
	detached  bool
	released  bool
	onRelease func()
}

var _ FullEngine = (*nativeFullEngine)(nil)
var _ FullInstance = (*nativeFullInstance)(nil)
var _ FullPendingAborter = (*nativeFullInstance)(nil)
var _ fullOwner = (*fullruntime.Owner)(nil)

func (e *nativeFullEngine) Start(ctx context.Context, id string, config FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, fmt.Errorf("persistent owner requires an instance ID")
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		return nil, err
	}
	// An explicit OCI target is pretrusted by IG, not signature-verified here.
	// This image/archive MUST come from administrator configuration, never a CRD.
	if err := handler.Init(params); err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.instances[id] != nil {
		e.mu.Unlock()
		return nil, fmt.Errorf("persistent instance ID %q is still owned", id)
	}
	owner, err := fullruntime.NewOwner(fullruntime.OwnerConfig{Program: config.Program, CgroupID: config.Binding.CgroupID, InitHostPID: config.Binding.PID, ControlRoot: e.controlRoot, Acquire: config.Acquire, ImageOrigins: config.ImageOrigins}, e.budget)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	instance := &nativeFullInstance{owner: owner, manager: e.manager, id: id}
	instance.onRelease = func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.instances[id] == instance {
			delete(e.instances, id)
		}
	}
	e.instances[id] = instance
	e.mu.Unlock()
	events := simple.New("sandbox-exec-full-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		return subscribeFullVerdicts(gc.GetDataSources()["verdict"], emit, e.onError)
	}))
	desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: e.image}}
	err = e.manager.StartGadget(ctx, desired,
		gadgetcontext.WithOrasReadonlyTarget(e.store),
		gadgetcontext.WithAdditionalDataOperators(handler, e.kube, fullruntime.New(), events),
		fullruntime.WithOwner(owner))
	// StartGadget joins failed startup cleanup. Even then Owner still owns pins
	// and its reservation; the caller receives this handle and must call Stop.
	instance.started = err == nil
	return instance, err
}

func subscribeFullVerdicts(ds datasource.DataSource, emit func(RawFullVerdict), onError func(error)) error {
	if ds == nil || ds.ByteOrder() == nil {
		return fmt.Errorf("missing full enforcement verdict datasource")
	}
	for name, kind := range map[string]api.Kind{"generation": api.Kind_Uint64, "cgroup": api.Kind_Uint64, "deny": api.Kind_Uint32, "mode": api.Kind_Uint32, "path_result": api.Kind_Int32, "host_pid": api.Kind_Uint32, "matched_rules": api.ArrayOf(api.Kind_Uint64), "error": api.Kind_Uint32} {
		field := ds.GetField(name)
		if field == nil || field.Type() != kind {
			return fmt.Errorf("missing or incompatible full verdict field %q", name)
		}
		size := uint32(4)
		if kind == api.Kind_Uint64 {
			size = 8
		}
		if name == "matched_rules" {
			size = 32
		}
		if field.Size() != 0 && field.Size() != size {
			return fmt.Errorf("invalid full verdict field size for %q", name)
		}
	}
	// Native BTF char arrays are CString; formatted datasource strings use
	// String. Both are read by the same String accessor, not byte-array guesses.
	path := ds.GetField("path")
	if path == nil || (path.Type() != api.Kind_CString && path.Type() != api.Kind_String) {
		return fmt.Errorf("missing or incompatible full verdict path")
	}
	return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		raw, err := ReadFullVerdict(ds, data)
		if err != nil {
			if onError != nil {
				onError(err)
			}
			return nil
		}
		if emit != nil {
			emit(raw)
		}
		return nil // Telemetry decode/export never changes enforcement lifecycle.
	}, 100)
}

func (i *nativeFullInstance) usable() error {
	if !i.started || i.retired || i.released {
		return fmt.Errorf("persistent instance is not running")
	}
	return nil
}
func (i *nativeFullInstance) Activate(ctx context.Context) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.usable(); err != nil {
		return fullruntime.PublicationResult{}, err
	}
	return i.owner.Activate(ctx)
}
func (i *nativeFullInstance) Update(ctx context.Context, program *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.usable(); err != nil {
		return fullruntime.PublicationResult{}, err
	}
	return i.owner.Update(ctx, program)
}
func (i *nativeFullInstance) Resume(ctx context.Context) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.usable(); err != nil {
		return fullruntime.PublicationResult{}, err
	}
	return i.owner.Resume(ctx)
}
func (i *nativeFullInstance) AbortPending(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.usable(); err != nil {
		return err
	}
	return i.owner.AbortPending(ctx)
}
func (i *nativeFullInstance) Check(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.usable(); err != nil {
		return err
	}
	return i.owner.Check(ctx)
}
func (i *nativeFullInstance) Generation() uint64        { return i.owner.Generation() }
func (i *nativeFullInstance) PendingGeneration() uint64 { return i.owner.PendingGeneration() }
func (i *nativeFullInstance) Epochs() map[string]uint64 { return i.owner.Epochs() }

func (i *nativeFullInstance) Detached() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.detached
}

// Stop must retire/drain BEFORE asking the manager to detach: IG continues
// teardown even when an operator's PreStop reports an error. Cancellation while
// joining retains the instance; only confirmed teardown permits pin release.
func (i *nativeFullInstance) Stop(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.released {
		return nil
	}
	if !i.retired {
		if err := i.owner.BeforeStop(ctx); err != nil {
			return err
		}
		i.retired = true
	}
	var stopErr error
	if !i.detached {
		stopErr = i.manager.StopGadget(ctx, i.id)
		if errors.Is(stopErr, instancemanager.ErrNotFound) {
			stopErr = nil
		}
		if stopErr != nil && i.manager.LookupInstance(i.id) != nil {
			return stopErr // A canceled wait may leave cleanup running/registered.
		}
		// StopGadget can join and remove an instance yet return its terminal Run
		// error. This engine exclusively owns its manager/IDs: absence after Stop
		// proves joined teardown, not just a failed/canceled observation. Preserve
		// that receipt and the error independently; pins can now be released.
		i.detached = true
	}
	if err := i.owner.ReleaseAfterDetach(); err != nil {
		return errors.Join(stopErr, err)
	}
	i.released = true
	if i.onRelease != nil {
		i.onRelease()
	}
	return stopErr
}

func (i *nativeFullInstance) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	source, ok := i.owner.(FullKernelCounterSource)
	if !ok {
		return fullruntime.KernelEventCounters{}, fmt.Errorf("native owner kernel counters unavailable")
	}
	return source.KernelEventCounters()
}
