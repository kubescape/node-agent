//go:build sandbox_shared_qualification

package igbackend

// G020 shared node engine (QUALIFICATION ONLY). One node-wide IG shared
// collection serves every binding: Start binds a cgroup to a route slot,
// Activate/UpdatePlan compile the binding's single policy through IG and
// publish it into that slot, Stop removes the binding and Close stops the
// node. It never reports Ready: Check always fails with
// errSharedQualificationOnly until the shared engine is signed off.
//
// Build: -tags sandbox_shared_qualification,enforce_exec_shared_qualification
// (the IG tag enables its qualification StartNode path; see
// sharedengine_qualification_guard.go).

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetapi "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2"
)

// SharedEngineAPIVersion is the IG shared-node API version this engine is
// written against; NewSharedQualificationEngine refuses any other.
const SharedEngineAPIVersion = 1

// SharedPublishAttempts bounds Compile/PublishCompiled retries when a
// compilation goes stale (fullruntime.ErrSharedCompiledStale).
const SharedPublishAttempts = 3

// Qualification-only defaults: the host procfs and root as mounted into the
// node-agent pod (hostPID is required for the host PID namespace).
const (
	SharedDefaultImageProcRoot = "/host/proc"
	SharedDefaultImageHostRoot = "/host"
)

const sharedGadgetID = "sandbox-shared-node"

// sharedRetiredScopes bounds the tombstones of retired (cgroup, scope)
// pairs; sharedUnboundReportInterval rate-limits unbound-cgroup reports.
const (
	sharedRetiredScopes         = 4096
	sharedUnboundReportInterval = 10 * time.Second
)

var errSharedQualificationOnly = fmt.Errorf("shared node engine is qualification-only and never Ready: %w", fullruntime.ErrSharedNativeUnavailable)

// SharedEngineConfig is administrator configuration, never policy input.
type SharedEngineConfig struct {
	Profile fullruntime.SharedProfile
	// Image names the trusted shared candidate image in Store (an explicit
	// OCI target is pretrusted by IG, not signature-verified here).
	Image string
	Store oras.ReadOnlyTarget
	// ContainerdAddress is the containerd socket as seen by the agent (empty:
	// no image index, FromImage policies are refused by IG). ImageProcRoot and
	// ImageHostRoot default to SharedDefaultImageProcRoot/HostRoot.
	ContainerdAddress            string
	ImageProcRoot, ImageHostRoot string
	FailClosedPollInterval       time.Duration
	RevisionDrainTimeout         time.Duration
}

func (c SharedEngineConfig) nodeConfig() fullruntime.SharedNodeConfig {
	n := fullruntime.SharedNodeConfig{Profile: c.Profile, ABI3Development: true, Image: c.Image, FailClosedPollInterval: c.FailClosedPollInterval, RevisionDrainTimeout: c.RevisionDrainTimeout, ContainerdAddress: c.ContainerdAddress, ImageProcRoot: c.ImageProcRoot, ImageHostRoot: c.ImageHostRoot}
	if n.ImageProcRoot == "" {
		n.ImageProcRoot = SharedDefaultImageProcRoot
	}
	if n.ImageHostRoot == "" {
		n.ImageHostRoot = SharedDefaultImageHostRoot
	}
	n.RecoveryDevelopment = strings.HasSuffix(c.Image, ":abi3-recovery-development")
	return n
}

// sharedNode and sharedSession are the IG surface this engine uses; unit
// tests replace them with fakes.
type sharedNode interface {
	Bind(context.Context, fullruntime.SharedBindingConfig) (sharedSession, error)
	StopNode(context.Context) error
	Ready() error
	KernelEventCounters() (fullruntime.KernelEventCounters, error)
	FailClosedHealth() (fullruntime.SharedFailClosedHealth, error)
	FactHealth() (fullruntime.SharedFactHealth, error)
}

type sharedSession interface {
	Compile(fullruntime.SharedBindingPolicy) (fullruntime.SharedCompiled, error)
	PublishCompiled(context.Context, fullruntime.SharedCompiled) (fullruntime.SharedRouteState, error)
	Inspect() fullruntime.SharedBindingStatus
	Remove(context.Context, uint64) error
}

// SharedEngine implements FullEngine and FullEngineCloser over one lazily
// started node. Events demultiplex by the bound cgroup and must carry the
// binding's route scope once it is known.
type SharedEngine struct {
	startMu sync.Mutex // serializes lazy StartNode and Close
	node    sharedNode
	closed  bool
	start   func(context.Context) (sharedNode, error)
	onError func(error)

	mu        sync.Mutex // instances and cgroups; never held across IG calls
	instances map[*sharedInstance]struct{}
	// cgroups demultiplexes node-wide events by the trusted binding cgroup
	// (the legacy cgroup field of every event), known from Bind on.
	cgroups map[uint64]*sharedInstance
	// retired tombstones the (cgroup, scope) pairs of stopped bindings, so
	// a retired binding's in-flight events are dropped rather than
	// attributed to a later binding of a reused cgroup ID. Bounded FIFO.
	retired      map[retiredScope]struct{}
	retiredOrder []retiredScope
	// Unbound-cgroup reports: at most one per sharedUnboundReportInterval,
	// carrying the count suppressed since the last one.
	now               func() time.Time
	unboundReported   time.Time
	unboundSuppressed uint64
}

type retiredScope struct{ cgroup, scope uint64 }

var _ FullEngine = (*SharedEngine)(nil)
var _ FullEngineCloser = (*SharedEngine)(nil)
var _ sharedAuditFaultEngine = (*SharedEngine)(nil)

// decodesSharedAuditFaults opts this engine's decoders into the G020 D1
// Audit fault (deny 1, mode 1, error 1: a would-deny operational error).
func (e *SharedEngine) decodesSharedAuditFaults() bool { return true }

// NewSharedQualificationEngine borrows the initialized runtime; the node
// starts on the first Start through a manager of that runtime.
func NewSharedQualificationEngine(rt runtime.Runtime, config SharedEngineConfig, onError func(error)) (*SharedEngine, error) {
	if fullruntime.SharedNodeAPIVersion != SharedEngineAPIVersion {
		return nil, fmt.Errorf("IG shared node API version %d, engine requires %d", fullruntime.SharedNodeAPIVersion, SharedEngineAPIVersion)
	}
	if rt == nil || config.Store == nil || config.Image == "" {
		return nil, fmt.Errorf("runtime and trusted shared candidate image/store are required")
	}
	if _, err := config.Profile.Validate(); err != nil {
		return nil, err
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	e := newSharedEngine(nil, onError)
	e.start = func(ctx context.Context) (sharedNode, error) { return e.startNode(ctx, manager, config) }
	return e, nil
}

func newSharedEngine(start func(context.Context) (sharedNode, error), onError func(error)) *SharedEngine {
	return &SharedEngine{start: start, onError: onError, instances: map[*sharedInstance]struct{}{}, cgroups: map[uint64]*sharedInstance{}, retired: map[retiredScope]struct{}{}, now: time.Now}
}

func (e *SharedEngine) report(err error) {
	if e.onError != nil {
		e.onError(err)
	}
}

// startNode runs the shared candidate image once through manager, with the
// verdict datasource subscribed by this engine's router.
func (e *SharedEngine) startNode(ctx context.Context, manager *instancemanager.Manager, config SharedEngineConfig) (sharedNode, error) {
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		return nil, err
	}
	if err := handler.Init(params); err != nil {
		return nil, err
	}
	real := &realSharedNode{}
	events := simple.New("sandbox-exec-shared-verdict", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		real.setContext(gc)
		return subscribeFullVerdicts(gc.GetDataSources()[fullruntime.SharedVerdictDataSource], e.route, e.onError)
	}))
	run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		desired := &gadgetapi.GadgetInstance{Id: sharedGadgetID, GadgetConfig: &gadgetapi.GadgetRunRequest{Version: gadgetapi.VersionGadgetRunProtocol, ImageName: config.Image}}
		err := manager.StartGadget(ctx, desired, gadgetcontext.WithOrasReadonlyTarget(config.Store), gadgetcontext.WithAdditionalDataOperators(handler, fullruntime.New(), events), opt)
		done := make(chan error, 1)
		if gi := manager.LookupInstance(sharedGadgetID); gi != nil {
			go func() { done <- gi.WaitStopped(context.Background()) }()
		}
		stop := func(ctx context.Context) error {
			err := manager.StopGadget(ctx, sharedGadgetID)
			if errors.Is(err, instancemanager.ErrNotFound) {
				return nil
			}
			if err != nil && manager.LookupInstance(sharedGadgetID) == nil {
				// Joined and removed: teardown happened; the run's terminal
				// error is telemetry, not a retained gadget.
				e.report(fmt.Errorf("shared node gadget ended: %w", err))
				return nil
			}
			return err
		}
		return stop, done, err
	}
	n, err := fullruntime.StartNode(fullruntime.WithSharedNodeQualification(ctx, fullruntime.SharedNodeQualification{Run: run}), config.nodeConfig())
	if err != nil {
		return nil, err
	}
	real.node = n
	return real, nil
}

func (e *SharedEngine) ensureNode(ctx context.Context) (sharedNode, error) {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.closed {
		return nil, fmt.Errorf("shared engine closed")
	}
	if e.node != nil {
		return e.node, nil
	}
	if e.start == nil {
		return nil, fmt.Errorf("shared engine has no node starter")
	}
	node, err := e.start(ctx)
	if err != nil {
		// StartNode joins its own teardown on failure; nothing is retained.
		return nil, fmt.Errorf("start shared node: %w", err)
	}
	if node == nil {
		return nil, fmt.Errorf("start shared node: no node")
	}
	e.node = node
	return node, nil
}

// Start binds the trusted binding to a route slot; Activate publishes.
func (e *SharedEngine) Start(ctx context.Context, id string, config FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id == "" || config.Program == nil || config.Acquire == nil || config.Binding.CgroupID == 0 || config.Binding.PID == 0 || config.Binding.ContainerName == "" {
		return nil, fmt.Errorf("shared binding requires an instance ID, program, lease, cgroup, init PID and container name")
	}
	node, err := e.ensureNode(ctx)
	if err != nil {
		return nil, err // Acquire never ran: the caller still owns its lease.
	}
	cgroup := config.Binding.CgroupID
	i := &sharedInstance{engine: e, binding: config.Binding, plan: config.Plan, program: config.Program, emit: emit, generations: map[uint64]uint64{}}
	// Reserve the cgroup before Bind: events demultiplex by it from the
	// kernel commit on, before any route scope is known.
	e.mu.Lock()
	if e.cgroups[cgroup] != nil {
		e.mu.Unlock()
		return nil, fmt.Errorf("cgroup %d is already bound by the shared engine", cgroup)
	}
	e.cgroups[cgroup] = i
	e.mu.Unlock()
	session, err := node.Bind(ctx, fullruntime.SharedBindingConfig{CgroupID: cgroup, InitHostPID: config.Binding.PID, ContainerID: config.Binding.ContainerID, Acquire: config.Acquire})
	if session == nil {
		e.mu.Lock()
		delete(e.cgroups, cgroup)
		e.mu.Unlock()
		return nil, errors.Join(err, errNilSession(err))
	}
	i.session = session
	e.mu.Lock()
	e.instances[i] = struct{}{}
	e.mu.Unlock()
	// A session returned with an error failed its cleanup: the caller must
	// retain this instance and retry Stop.
	return i, err
}

func errNilSession(err error) error {
	if err != nil {
		return nil
	}
	return fmt.Errorf("shared node returned no binding session")
}

// route delivers one node-wide verdict event to the binding owning its
// cgroup; once the binding's route scope is known the event must carry it.
func (e *SharedEngine) route(raw RawFullVerdict) {
	if !raw.Shared {
		e.report(fmt.Errorf("shared verdict without scope (generation %d, cgroup %d)", raw.Generation, raw.Cgroup))
		return
	}
	e.mu.Lock()
	if _, retired := e.retired[retiredScope{raw.Cgroup, raw.Scope}]; retired {
		// In flight from a stopped binding: never another binding's.
		e.mu.Unlock()
		return
	}
	i := e.cgroups[raw.Cgroup]
	var unbound error
	if i == nil {
		if now := e.now(); e.unboundReported.IsZero() || now.Sub(e.unboundReported) >= sharedUnboundReportInterval {
			unbound = fmt.Errorf("shared verdict for unbound cgroup %d (scope %d; %d earlier unbound verdicts suppressed)", raw.Cgroup, raw.Scope, e.unboundSuppressed)
			e.unboundReported, e.unboundSuppressed = now, 0
		} else {
			e.unboundSuppressed++
		}
	}
	e.mu.Unlock()
	if i == nil {
		if unbound != nil {
			e.report(unbound)
		}
		return
	}
	i.deliver(raw)
}

// unregister forgets i and tombstones its (cgroup, scope).
func (e *SharedEngine) unregister(i *sharedInstance, scope uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.instances, i)
	if e.cgroups[i.binding.CgroupID] == i {
		delete(e.cgroups, i.binding.CgroupID)
	}
	if scope == 0 {
		return
	}
	key := retiredScope{i.binding.CgroupID, scope}
	if _, ok := e.retired[key]; ok {
		return
	}
	if len(e.retiredOrder) >= sharedRetiredScopes {
		delete(e.retired, e.retiredOrder[0])
		e.retiredOrder = e.retiredOrder[1:]
	}
	e.retired[key] = struct{}{}
	e.retiredOrder = append(e.retiredOrder, key)
}

// Close stops the node after every instance was stopped. An error retains it.
func (e *SharedEngine) Close(ctx context.Context) error {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	e.mu.Lock()
	live := len(e.instances)
	e.mu.Unlock()
	if live != 0 {
		return fmt.Errorf("shared engine still owns %d bindings", live)
	}
	if e.node != nil {
		if err := e.node.StopNode(ctx); err != nil {
			return err
		}
		e.node = nil
	}
	e.closed = true
	return nil
}

type sharedInstance struct {
	engine  *SharedEngine
	session sharedSession
	binding sandboxpolicy.Binding
	emit    func(RawFullVerdict)

	mu sync.Mutex // lifecycle (also serialized by the backend)
	// plan/program are the first activation's inputs (FullStartConfig).
	plan       sandboxpolicy.Plan
	program    *fullpolicy.KernelProgram
	generation uint64 // backend generation of the committed publication
	// epochs are the committed root epochs in backend generations (what
	// CompileFull needs); routeEpochs are IG's, in route generations.
	epochs, routeEpochs map[string]uint64
	removed             bool
	// pending is the backend generation of a publication whose outcome is
	// unknown (PublishCompiled failed other than stale): its route staging
	// pendingRoute is kept, so events the kernel may already produce still
	// decode, until Resume republishes it or AbortPending discards it.
	pending        uint64
	pendingRoute   uint64
	pendingPlan    sandboxpolicy.Plan
	pendingProgram *fullpolicy.KernelProgram

	genMu sync.Mutex
	// generations maps a staged or committed route generation (what the
	// kernel reports) to the backend generation whose provenance decodes it.
	generations map[uint64]uint64
	committed   uint64 // route generation of the committed publication
	scope       uint64 // route scope, known before the first staging (0 before)
	// Verdicts before the scope is known (the live commit-to-receipt window):
	// at most one report per sharedUnboundReportInterval, the rest counted.
	unknownReported   time.Time
	unknownSuppressed uint64
}

var _ FullInstance = (*sharedInstance)(nil)
var _ FullPlanUpdater = (*sharedInstance)(nil)
var _ FullPendingAborter = (*sharedInstance)(nil)

func (i *sharedInstance) deliver(raw RawFullVerdict) {
	i.genMu.Lock()
	generation, scope := i.generations[raw.Generation], i.scope
	var unknown error
	if scope == 0 {
		if now := i.engine.now(); i.unknownReported.IsZero() || now.Sub(i.unknownReported) >= sharedUnboundReportInterval {
			unknown = fmt.Errorf("shared verdict scope %d does not match cgroup %d's route scope 0 (not yet known; %d earlier verdicts suppressed)", raw.Scope, raw.Cgroup, i.unknownSuppressed)
			i.unknownReported, i.unknownSuppressed = now, 0
		} else {
			i.unknownSuppressed++
		}
	}
	i.genMu.Unlock()
	if scope == 0 {
		// Never attributed without a known scope; reports are rate-limited.
		if unknown != nil {
			i.engine.report(unknown)
		}
		return
	}
	if raw.Scope != scope {
		// The scope is registered before anything is staged: an event
		// without a known, matching scope is never attributed.
		i.engine.report(fmt.Errorf("shared verdict scope %d does not match cgroup %d's route scope %d", raw.Scope, raw.Cgroup, scope))
		return
	}
	if generation == 0 {
		i.engine.report(fmt.Errorf("shared verdict for unknown route generation %d (scope %d)", raw.Generation, raw.Scope))
		return
	}
	raw.Generation = generation
	if i.emit != nil {
		i.emit(raw)
	}
}

// stage installs route->backend generation provenance before the kernel
// commit can produce events for it, evicting the oldest uncommitted entry.
func (i *sharedInstance) stage(route, generation uint64) {
	i.genMu.Lock()
	defer i.genMu.Unlock()
	if len(i.generations) >= FullVerdictCatalogCapacity {
		var oldest uint64
		for g := range i.generations {
			if g != i.committed && (oldest == 0 || g < oldest) {
				oldest = g
			}
		}
		delete(i.generations, oldest)
	}
	i.generations[route] = generation
}

func (i *sharedInstance) unstage(route uint64) {
	i.genMu.Lock()
	defer i.genMu.Unlock()
	if route != i.committed {
		delete(i.generations, route)
	}
}

// registerScope records the binding's route scope before anything is staged
// when IG already knows it (a protocol registration's scope cookie), so
// events are checked against it from the kernel commit on. The live product
// publisher instead mints the route scope inside the first publication
// (shared_product_commander.go: a random scope per adopted slot) and
// ScopeCookie stays 0: commit then learns it from the receipt. Until then no
// event is attributed (deliver requires a known, matching scope), so verdicts
// raced between the kernel commit and the receipt are reported, never
// misattributed.
func (i *sharedInstance) registerScope() error {
	i.genMu.Lock()
	known := i.scope
	i.genMu.Unlock()
	if known != 0 {
		return nil
	}
	cookie := i.session.Inspect().ScopeCookie
	if cookie == 0 {
		return nil // learned from the first commit's receipt
	}
	i.genMu.Lock()
	defer i.genMu.Unlock()
	if i.scope == 0 {
		i.scope = cookie
	}
	return nil
}

func (i *sharedInstance) routeScope() uint64 {
	i.genMu.Lock()
	defer i.genMu.Unlock()
	return i.scope
}

// commit records the committed route generation and checks the receipt's
// scope against the registered one, which never changes (IG refuses a
// publication that changes it). Without a pre-registered scope the first
// nonzero receipt scope becomes the registered one. A mismatching or zero
// receipt scope is a fault; events stay checked against the registered scope
// (none while it is unknown).
func (i *sharedInstance) commit(route, scope uint64) error {
	i.genMu.Lock()
	defer i.genMu.Unlock()
	i.committed = route
	if scope == 0 {
		return fmt.Errorf("shared route %d committed without a scope", route)
	}
	if i.scope == 0 {
		i.scope = scope
		return nil
	}
	if i.scope != scope {
		return fmt.Errorf("shared route scope %d does not match the registered scope %d", scope, i.scope)
	}
	return nil
}

func (i *sharedInstance) Activate(ctx context.Context) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.generation != 0 {
		return fullruntime.PublicationResult{}, fmt.Errorf("shared binding already activated")
	}
	return i.publishLocked(ctx, i.plan, i.program)
}

// Update cannot publish without the plan; the backend uses UpdatePlan.
func (i *sharedInstance) Update(context.Context, *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	return fullruntime.PublicationResult{}, fmt.Errorf("shared engine publishes resolved plans only (UpdatePlan)")
}

func (i *sharedInstance) UpdatePlan(ctx context.Context, plan sandboxpolicy.Plan, program *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.publishLocked(ctx, plan, program)
}

// publishLocked compiles plan's single policy through IG at the route's next
// generation, checks that its matched-rule mapping equals the backend's
// provenance for program, stages route->backend generation and publishes.
// A stale compilation is dropped and recompiled (bounded). Publication is
// all-or-nothing: nothing ever remains pending.
func (i *sharedInstance) publishLocked(ctx context.Context, plan sandboxpolicy.Plan, program *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	if i.removed {
		return fullruntime.PublicationResult{}, fmt.Errorf("shared binding removed")
	}
	if err := fullpolicy.ValidateKernelProgram(program); err != nil {
		return fullruntime.PublicationResult{}, err
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](program.Entries[0])
	if err != nil {
		return fullruntime.PublicationResult{}, err
	}
	policies, err := fullPolicies(i.binding, plan)
	if err != nil {
		return fullruntime.PublicationResult{}, err
	}
	source, err := fullruntime.SharedSinglePolicy(policies) // D3: multi-policy refused
	if err != nil {
		return fullruntime.PublicationResult{}, err
	}
	input := fullruntime.SharedBindingPolicy{Source: source, Container: i.binding.ContainerName}
	for attempt := 0; attempt < SharedPublishAttempts; attempt++ {
		compiled, err := i.session.Compile(input)
		if err != nil {
			return fullruntime.PublicationResult{}, err
		}
		if compiled.Program == nil || compiled.Generation == 0 || !reflect.DeepEqual(compiled.Program.Rules, program.Rules) {
			return fullruntime.PublicationResult{}, fmt.Errorf("shared compilation does not match the backend's verdict provenance")
		}
		if err := i.registerScope(); err != nil {
			return fullruntime.PublicationResult{}, err
		}
		i.stage(compiled.Generation, header.Generation)
		state, err := i.session.PublishCompiled(ctx, compiled)
		if errors.Is(err, fullruntime.ErrSharedCompiledStale) {
			// Refused before any command ran: nothing can be committed.
			i.unstage(compiled.Generation)
			i.pending, i.pendingRoute, i.pendingPlan, i.pendingProgram = 0, 0, sandboxpolicy.Plan{}, nil
			continue
		}
		if err != nil {
			// The outcome may be unknown (the kernel may have committed):
			// keep the staging pending until Resume or AbortPending.
			i.pending, i.pendingRoute, i.pendingPlan, i.pendingProgram = header.Generation, compiled.Generation, plan, program
			return fullruntime.PublicationResult{}, err
		}
		i.pending, i.pendingRoute, i.pendingPlan, i.pendingProgram = 0, 0, sandboxpolicy.Plan{}, nil
		var mismatch error
		if state.Generation != compiled.Generation {
			// Committed, but at an unexpected generation: keep decoding it and
			// report the protocol fault alongside the committed result.
			i.unstage(compiled.Generation)
			i.stage(state.Generation, header.Generation)
			mismatch = fmt.Errorf("shared route committed generation %d, compiled for %d", state.Generation, compiled.Generation)
		}
		if err := i.commit(state.Generation, state.Scope); err != nil {
			mismatch = errors.Join(mismatch, err)
		}
		i.generation = header.Generation
		// IG epochs are route generations; the backend compiles its
		// provenance at its own generations. A retained IG epoch keeps the
		// policy's backend epoch, a new one is an activation at this one.
		epochs := make(map[string]uint64, len(compiled.Epochs))
		for id, epoch := range compiled.Epochs {
			if previous, ok := i.routeEpochs[id]; ok && previous == epoch && i.epochs[id] != 0 {
				epochs[id] = i.epochs[id]
			} else {
				epochs[id] = header.Generation
			}
		}
		i.epochs, i.routeEpochs = epochs, compiled.Epochs
		return fullruntime.PublicationResult{Committed: true, Generation: header.Generation}, mismatch
	}
	return fullruntime.PublicationResult{}, fmt.Errorf("shared compilation stale after %d attempts: %w", SharedPublishAttempts, fullruntime.ErrSharedCompiledStale)
}

// Resume republishes a publication whose outcome was unknown.
func (i *sharedInstance) Resume(ctx context.Context) (fullruntime.PublicationResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.pending == 0 {
		return fullruntime.PublicationResult{}, fmt.Errorf("shared publication has nothing pending")
	}
	return i.publishLocked(ctx, i.pendingPlan, i.pendingProgram)
}

// AbortPending discards an unknown-outcome publication superseded by the
// backend, with its route staging.
func (i *sharedInstance) AbortPending(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.pending == 0 {
		return nil
	}
	i.genMu.Lock()
	if i.generations[i.pendingRoute] == i.pending && i.pendingRoute != i.committed {
		delete(i.generations, i.pendingRoute)
	}
	i.genMu.Unlock()
	i.pending, i.pendingRoute, i.pendingPlan, i.pendingProgram = 0, 0, sandboxpolicy.Plan{}, nil
	return nil
}

func (i *sharedInstance) Generation() uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.generation
}

func (i *sharedInstance) PendingGeneration() uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.pending
}

func (i *sharedInstance) Epochs() map[string]uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make(map[string]uint64, len(i.epochs))
	for k, v := range i.epochs {
		out[k] = v
	}
	return out
}

// Check reports the binding's route health and always fails: the shared
// engine never confirms protection before sign-off.
func (i *sharedInstance) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status := i.session.Inspect()
	return errors.Join(errSharedQualificationOnly, status.Fault)
}

func (i *sharedInstance) Detached() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.removed
}

// Stop removes the binding at its route's generation. The physical account
// (pins, slot) is released only by node teardown (Close).
func (i *sharedInstance) Stop(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.removed {
		return nil
	}
	var generation uint64
	if status := i.session.Inspect(); status.RoutePublished {
		generation = status.Generation
	}
	if err := i.session.Remove(ctx, generation); err != nil {
		return err
	}
	i.removed = true
	scope := i.routeScope()
	if scope == 0 {
		scope = i.session.Inspect().ScopeCookie
	}
	i.engine.unregister(i, scope)
	return nil
}

// SharedNodeHealth is one reading of the node's health witnesses.
type SharedNodeHealth struct {
	Started                        bool
	Ready, FailClosedErr, FactsErr error
	CountersErr                    error
	FailClosed                     fullruntime.SharedFailClosedHealth
	Facts                          fullruntime.SharedFactHealth
	Counters                       fullruntime.KernelEventCounters
}

// Health reads the node's witnesses without starting it.
func (e *SharedEngine) Health() SharedNodeHealth {
	e.startMu.Lock()
	node := e.node
	e.startMu.Unlock()
	if node == nil {
		return SharedNodeHealth{}
	}
	h := SharedNodeHealth{Started: true, Ready: node.Ready()}
	h.FailClosed, h.FailClosedErr = node.FailClosedHealth()
	h.Facts, h.FactsErr = node.FactHealth()
	h.Counters, h.CountersErr = node.KernelEventCounters()
	return h
}

// ApplySharedNodeHealth maps h into status: Ready is always False (reason
// SharedNodeNotStarted, SharedNodeNotReady when the fail-closed witness is
// NotReady or unknown, otherwise QualificationOnly) and a Degraded condition
// reports fail-closed Degraded, verdict event loss (D2: never NotReady on its
// own) and unavailable witnesses.
func ApplySharedNodeHealth(status *api.NodeStatus, h SharedNodeHealth, observedGeneration int64, now metav1.Time) {
	ready := metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "QualificationOnly", ObservedGeneration: observedGeneration, LastTransitionTime: now}
	degraded := metav1.Condition{Type: "Degraded", Status: metav1.ConditionFalse, Reason: "Healthy", ObservedGeneration: observedGeneration, LastTransitionTime: now}
	var notReady, reasons, details []string
	switch {
	case !h.Started:
		ready.Reason, ready.Message = "SharedNodeNotStarted", "shared node not started"
	default:
		if h.FailClosedErr != nil {
			notReady = append(notReady, "fail-closed witness: "+h.FailClosedErr.Error())
		} else if h.FailClosed.State == fullruntime.SharedFailClosedUnknown || h.FailClosed.State == fullruntime.SharedFailClosedNotReady {
			notReady = append(notReady, "fail-closed rate "+h.FailClosed.State.String())
		}
		if errors.Is(h.Ready, fullruntime.ErrSharedFailClosedNotReady) {
			notReady = append(notReady, "node fail-closed NotReady")
		}
		if h.FailClosedErr == nil && h.FailClosed.State == fullruntime.SharedFailClosedDegraded || errors.Is(h.Ready, fullruntime.ErrSharedFailClosedDegraded) {
			reasons = append(reasons, "FailClosedDegraded")
		}
		if errors.Is(h.Ready, fullruntime.ErrSharedVerdictEventLoss) {
			reasons = append(reasons, "VerdictEventLoss")
		}
		if h.CountersErr != nil {
			reasons = append(reasons, "VerdictCountersUnavailable")
			details = append(details, "verdict counters: "+h.CountersErr.Error())
		}
		if h.FactsErr != nil {
			reasons = append(reasons, "FactWitnessUnavailable")
			details = append(details, "fact witness: "+h.FactsErr.Error())
		}
		details = append(details, fmt.Sprintf("verdict events submitted=%d lost=%d observationErrors=%d", h.Counters.Submitted, h.Counters.Lost, h.Counters.ObservationErrors))
		if h.FactsErr == nil {
			details = append(details, fmt.Sprintf("fact passes=%d targetMissing=%d actorMissing=%d fsUnknown=%d stdinUnknown=%d ancestorUnknown=%d", h.Facts.Passes, h.Facts.TargetMissing, h.Facts.ActorMissing, h.Facts.FSUnknown, h.Facts.StdinUnknown, h.Facts.AncestorUnknown))
		}
		if len(notReady) != 0 {
			ready.Reason = "SharedNodeNotReady"
		}
		ready.Message = strings.Join(append(append([]string{errSharedQualificationOnly.Error()}, notReady...), details...), "; ")
		if len(reasons) != 0 {
			sort.Strings(reasons)
			degraded.Status, degraded.Reason, degraded.Message = metav1.ConditionTrue, strings.Join(reasons, ","), strings.Join(details, "; ")
		}
	}
	conditions := []metav1.Condition{ready, degraded}
	for _, c := range status.Conditions {
		if c.Type != "Ready" && c.Type != "Degraded" {
			conditions = append(conditions, c)
		}
	}
	status.Conditions = conditions
}

// realSharedNode adapts *fullruntime.NodeEnforcer.
type realSharedNode struct {
	node *fullruntime.NodeEnforcer
	mu   sync.Mutex
	gc   operators.GadgetContext
}

func (n *realSharedNode) setContext(gc operators.GadgetContext) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.gc = gc
}

func (n *realSharedNode) Bind(ctx context.Context, c fullruntime.SharedBindingConfig) (sharedSession, error) {
	s, err := n.node.Bind(ctx, c)
	if s == nil {
		return nil, err
	}
	return s, err
}

func (n *realSharedNode) StopNode(ctx context.Context) error { return n.node.StopNode(ctx) }

func (n *realSharedNode) Ready() error {
	n.mu.Lock()
	gc := n.gc
	n.mu.Unlock()
	if gc == nil {
		return fmt.Errorf("shared node gadget context unavailable: %w", fullruntime.ErrSharedNativeUnavailable)
	}
	return n.node.Ready(gc)
}

func (n *realSharedNode) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	return n.node.KernelEventCounters()
}

func (n *realSharedNode) FailClosedHealth() (fullruntime.SharedFailClosedHealth, error) {
	return n.node.FailClosedHealth()
}

func (n *realSharedNode) FactHealth() (fullruntime.SharedFactHealth, error) {
	return n.node.FactHealth()
}
