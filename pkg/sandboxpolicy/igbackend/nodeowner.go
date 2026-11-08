package igbackend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// NodeInstance is one running node-wide gadget instance.
type NodeInstance interface {
	Ready() error
	// SlotHealth fails when the instance counted a fault in the slot (for
	// privilege: a task of an enforcing slot may be untracked).
	SlotHealth(slot uint32) error
	Bind(enforcement.Binding) error
	Unbind(enforcement.ContainerIdentity) error
	Stop(context.Context) error
}

// NodeStats counts how container binds found their policy slot.
type NodeStats struct {
	// Prepared: the slot already existed (created when the pod was scheduled,
	// or used by another container), so the bind was a live map write.
	Prepared uint64
	// Replaced: the slot was missing, so the node instance was replaced.
	Replaced uint64
	// Replacements counts every node instance replacement.
	Replacements uint64
}

// nodeSection is what a node owner needs from one policy section. C is the
// section's compiled policy.
type nodeSection[C any] struct {
	name string
	// combination returns the section's policies of a plan, sorted, and
	// their key. Containers with the same key share a slot.
	combination func(sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy)
	// compile compiles one instance: slot i holds the policies slots[i].
	compile func(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) (C, error)
	start   func(ctx context.Context, id string, compiled C, bindings []enforcement.Binding) (NodeInstance, error)
	// startEmpty makes Prepare start an instance with no slot when none
	// runs, so the first container does not wait for the slow first gadget
	// load.
	startEmpty bool
	// arming: a bind arms the tasks already in the cgroup (privilege). A pod
	// binding then skips the arming (see nativePod).
	arming bool
}

type nodeBinding struct {
	binding     sandboxpolicy.Binding
	revision    string
	combination string
	// lease pins the live container identity while it is bound (nil when the
	// backend has no validator).
	lease Lease
}

func (p *nodeBinding) check() error {
	if p.lease == nil {
		return nil
	}
	return p.lease.Check()
}

func (p *nodeBinding) close() error {
	if p.lease == nil {
		return nil
	}
	return p.lease.Close()
}

// podBinding is a bound pod cgroup (see sandboxpolicy.PodBinding).
type podBinding struct {
	pod         sandboxpolicy.PodBinding
	combination string
}

// podRuntime is the runtime name of a pod cgroup identity in the bindings
// controller. No container runtime has this name.
const podRuntime = "kubernetes-pod"

// nativePod returns the bindings controller identity of a pod cgroup. With
// arming, the tasks already in it are not armed: runc init of a container
// being created can be there. A section without arming has nothing to skip.
func (b *nodeOwner[C]) nativePod(p sandboxpolicy.PodBinding, slot uint32) enforcement.Binding {
	return enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: string(p.PodUID), CgroupID: p.CgroupID, CgroupPath: p.CgroupPath}, Slot: slot, SkipArming: b.section.arming}
}

// emptyRetry is the shortest time between two starts of an instance with no
// slot: each start is a slow gadget load on the refresh loop.
const emptyRetry = 30 * time.Second

// healRetry is the shortest time between two new instances started only to
// heal tracking faults. Faults recur under memory pressure; a gadget reload on
// every reconcile would add load then. The binding stays unconfirmed meanwhile.
const healRetry = 30 * time.Second

// nodeOwner owns ONE gadget instance per node for one section.
//
// A slot is one combination of the section's policies; containers with the
// same combination share it. Binding or unbinding a container is a live map
// write. A combination that the running instance does not have (a new or
// changed policy) replaces the node instance: start the candidate with every
// slot in use, wait until it is ready with every container bound, then stop
// the old instance. Both enforce during the overlap. Unused slots are dropped
// at the next replacement.
type nodeOwner[C any] struct {
	mu           sync.Mutex
	section      nodeSection[C]
	validator    Validator
	prefix       string
	generation   uint64
	instance     NodeInstance
	slots        map[string]uint32 // combination -> slot in instance
	combinations map[string][]sandboxpolicy.CompiledPolicy
	bindings     map[identity]*nodeBinding
	pods         map[types.UID]*podBinding
	prepared     map[string][]sandboxpolicy.CompiledPolicy
	retiring     []NodeInstance
	stats        NodeStats
	closed       bool
	// emptyFailed is when starting an instance with no slot last failed.
	emptyFailed time.Time
	// unfit is how many prepared combinations did not fit at the last
	// Prepare that checked (logged when it changes).
	unfit int
	// lastHeal is when a tracking fault last started a new instance.
	lastHeal time.Time
	// retired sums the last counter reading of each stopped instance.
	retired            enforcement.VerdictCounters
	retiredUnavailable uint64
	// tables: see remember. Own lock, because a reporter reads it while a
	// replacement holds mu. generations maps each instance that runs or
	// still stops (under mu) to its table.
	tablesMu    sync.Mutex
	tables      map[uint64][][]sandboxpolicy.CompiledPolicy
	generations map[NodeInstance]uint64
	// unavailable is the EnforcementUnavailableError of the last start, nil
	// after a start that worked. It has its own lock: the controller reads
	// it under its own lock, and mu is held during a slow start.
	unavailableMu sync.Mutex
	unavailable   error
}

// Unavailable returns why the last instance start found the section
// unenforceable on this node (sandboxpolicy.RuntimeAvailability), or nil.
func (b *nodeOwner[C]) Unavailable() error {
	b.unavailableMu.Lock()
	defer b.unavailableMu.Unlock()
	return b.unavailable
}

// recordStart keeps the EnforcementUnavailableError of a start; a start that
// worked clears it, and another error keeps the last value.
func (b *nodeOwner[C]) recordStart(err error) {
	var u *sandboxpolicy.EnforcementUnavailableError
	if err != nil && !errors.As(err, &u) {
		return
	}
	b.unavailableMu.Lock()
	defer b.unavailableMu.Unlock()
	b.unavailable = nil
	if u != nil {
		b.unavailable = u
	}
}

func newNodeOwner[C any](section nodeSection[C], validator Validator, prefix string) nodeOwner[C] {
	return nodeOwner[C]{section: section, validator: validator, prefix: prefix, slots: map[string]uint32{}, combinations: map[string][]sandboxpolicy.CompiledPolicy{}, bindings: map[identity]*nodeBinding{}, pods: map[types.UID]*podBinding{}, prepared: map[string][]sandboxpolicy.CompiledPolicy{}}
}

// logBind records whether a new container found its slot ready ("prepared")
// or needed a node instance replacement ("replaced").
func (b *nodeOwner[C]) logBind(binding sandboxpolicy.Binding, slot string) {
	logger.L().Info("sandbox "+b.section.name+" bind", helpers.String("slot", slot),
		helpers.String("namespace", binding.Namespace), helpers.String("pod", binding.PodName), helpers.String("container", binding.ContainerName))
}

func (b *nodeOwner[C]) Stats() NodeStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *nodeOwner[C]) Replace(ctx context.Context, binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) (sandboxpolicy.ReplaceResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	current := b.bindings[k]
	var result sandboxpolicy.ReplaceResult
	var health error
	if current != nil {
		result.ActiveRevision = current.revision
		health = b.health(current)
		result.ProtectionUnconfirmed = health != nil
	}
	if b.closed {
		return result, fmt.Errorf("%s backend is closed", b.section.name)
	}
	combination, policies := b.section.combination(plan)
	if len(policies) == 0 {
		return result, fmt.Errorf("plan has no %s section", b.section.name)
	}
	if b.instance != nil && health == nil {
		health = b.instance.Ready()
	}
	if current != nil && current.revision == plan.Revision && current.combination == combination && health == nil {
		result.Committed = true
		return result, b.retire(ctx)
	}
	if current != nil && current.revision == plan.Revision && current.combination == combination &&
		b.instance.Ready() == nil && current.check() == nil {
		// Only tracking faults: heal with a new instance, at most every healRetry.
		if time.Since(b.lastHeal) < healRetry {
			return result, health
		}
		b.lastHeal = time.Now()
	}
	next := &nodeBinding{binding: binding, revision: plan.Revision, combination: combination}
	if current != nil && current.lease != nil && current.check() == nil {
		next.lease = current.lease
	} else if b.validator != nil {
		lease, err := b.validator.Acquire(ctx, binding)
		if err != nil {
			return result, err
		}
		next.lease = lease
	}
	commit := func() (sandboxpolicy.ReplaceResult, error) {
		var errs []error
		if current != nil && current.lease != nil && current.lease != next.lease {
			errs = append(errs, current.close())
		}
		errs = append(errs, b.retire(ctx))
		return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: plan.Revision}, errors.Join(errs...)
	}
	fail := func(err error) (sandboxpolicy.ReplaceResult, error) {
		if next.lease != nil && (current == nil || next.lease != current.lease) {
			err = errors.Join(err, next.close())
		}
		return result, err
	}
	if slot, ok := b.slots[combination]; ok && b.instance != nil && health == nil {
		if err := b.instance.Bind(enforcement.Binding{Container: native(binding), Slot: slot}); err != nil {
			return fail(err)
		}
		if current == nil {
			b.stats.Prepared++
			b.logBind(binding, "prepared")
		}
		b.bindings[k] = next
		return commit()
	}
	extra := map[string][]sandboxpolicy.CompiledPolicy{combination: policies}
	err := b.replaceInstance(ctx, b.prepared, extra, k, next, true)
	if err != nil && len(b.prepared) > 0 {
		// The speculative prepared slots may not fit: drop only those. The
		// active pod bindings stay; if the candidate still does not fit, the
		// new binding is refused.
		err = b.replaceInstance(ctx, nil, extra, k, next, true)
	}
	if err != nil {
		return fail(err)
	}
	if current == nil {
		b.stats.Replaced++
		b.logBind(binding, "replaced")
	}
	return commit()
}

func (b *nodeOwner[C]) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	current := b.bindings[k]
	if current == nil {
		return sandboxpolicy.WithdrawResult{Committed: true}, b.retire(ctx)
	}
	// An instance that is not ready protects nothing, so the removal is
	// already true; only a ready instance must drop the map entry first.
	if b.instance != nil && b.instance.Ready() == nil {
		if err := b.instance.Unbind(native(binding)); err != nil {
			return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, err
		}
	}
	delete(b.bindings, k)
	return sandboxpolicy.WithdrawResult{Committed: true}, errors.Join(current.close(), b.retire(ctx))
}

func (b *nodeOwner[C]) Attest(_ context.Context, binding sandboxpolicy.Binding, revision string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.bindings[key(binding)]
	if current == nil || current.revision != revision || b.instance == nil {
		return fmt.Errorf("%s revision %q is not active", b.section.name, revision)
	}
	return b.health(current)
}

// health checks the instance, the slot's faults and the identity lease of one
// bound container. A fault makes the next same-plan Replace start a new
// instance.
func (b *nodeOwner[C]) health(p *nodeBinding) error {
	slot, ok := b.slots[p.combination]
	if !ok {
		return errors.Join(fmt.Errorf("%s combination has no slot", b.section.name), b.instance.Ready(), p.check())
	}
	return errors.Join(b.instance.Ready(), b.instance.SlotHealth(slot), p.check())
}

// Prepare declares the combinations that containers will need, so they find
// their slot and bind with a live map write. The plans are those of the pods
// scheduled to this node that are not finished, then one plan per active
// policy (Controller.PrepareScheduled): so a slot for each policy exists before
// any pod matches it, from the first start on. A missing combination replaces
// the node instance now. Combinations no longer prepared and not in use are
// dropped at the next replacement. When the combinations do not all fit in one
// instance, the ones that fit are prepared, in the order given (so pod plans
// before policy plans), and the others are logged; they are not an error.
func (b *nodeOwner[C]) Prepare(ctx context.Context, plans []sandboxpolicy.Plan) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("%s backend is closed", b.section.name)
	}
	prepared := map[string][]sandboxpolicy.CompiledPolicy{}
	var order []string
	for _, plan := range plans {
		combination, policies := b.section.combination(plan)
		if len(policies) == 0 {
			continue
		}
		if _, ok := prepared[combination]; !ok {
			order = append(order, combination)
		}
		prepared[combination] = policies
	}
	if b.missing(prepared) {
		var unfit int
		prepared, unfit = b.fit(order, prepared)
		if unfit != b.unfit {
			b.unfit = unfit
			if unfit > 0 {
				logger.L().Warning("sandbox "+b.section.name+" prepare: policy combinations do not fit in one instance, not prepared",
					helpers.Int("prepared", len(prepared)), helpers.Int("notPrepared", unfit))
			}
		}
	}
	if !b.missing(prepared) {
		b.prepared = prepared
		return b.retire(ctx)
	}
	// The prepared set is kept only when the instance with it is running.
	err := b.replaceInstance(ctx, prepared, nil, identity{}, nil, true)
	if err != nil && len(prepared) == 0 {
		b.emptyFailed = time.Now()
	}
	return errors.Join(err, b.retire(ctx))
}

// missing reports whether Prepare must start an instance: a prepared
// combination has no slot, or, with startEmpty, no instance runs (a start with
// no slot waits emptyRetry after a failed one). The first gadget load is slow,
// so with no instance the first container of a policy would find none ready
// (for example the first pod after a node-agent restart).
func (b *nodeOwner[C]) missing(prepared map[string][]sandboxpolicy.CompiledPolicy) bool {
	for combination := range prepared {
		if _, ok := b.slots[combination]; !ok {
			return true
		}
	}
	return b.section.startEmpty && b.instance == nil && time.Since(b.emptyFailed) >= emptyRetry
}

// fit returns the prepared combinations that compile in one instance with every
// combination in use (container and pod bindings), and the number left out. It
// keeps all when they fit; else it adds them one at a time in order and skips
// each one that does not fit (the slot limit of the gadget, or its other map
// limits). The compile is only a check: it starts nothing.
func (b *nodeOwner[C]) fit(order []string, prepared map[string][]sandboxpolicy.CompiledPolicy) (map[string][]sandboxpolicy.CompiledPolicy, int) {
	compiles := func(wanted map[string][]sandboxpolicy.CompiledPolicy) bool {
		_, policies := slotList(wanted)
		_, err := b.section.compile(b.generation+1, policies)
		return err == nil
	}
	if compiles(b.wanted(prepared, nil, b.bindings, b.pods)) {
		return prepared, 0
	}
	wanted := b.wanted(nil, nil, b.bindings, b.pods)
	fitted := map[string][]sandboxpolicy.CompiledPolicy{}
	for _, c := range order {
		if _, ok := wanted[c]; !ok {
			wanted[c] = prepared[c]
			if !compiles(wanted) {
				delete(wanted, c)
				continue
			}
		}
		fitted[c] = prepared[c]
	}
	return fitted, len(prepared) - len(fitted)
}

// ClearPrepared drops the prepared set when the section has no active policy.
// It never starts an instance: the dropped combinations leave at the next
// replacement, as in Prepare.
func (b *nodeOwner[C]) ClearPrepared(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
	return b.retire(ctx)
}

// BindPods binds the given pod cgroups to the slot of their plan and unbinds
// the pod cgroups that are not given (sandboxpolicy.PodBinder). It is the same
// for every section: a pod is bound only when its plan has policies of this
// section (Controller.PodPlans keeps a section only when every container of
// the pod gets the same policies of it). A pod whose slot does not exist yet
// is skipped: Prepare creates the slot, and the next call binds the pod. A pod
// whose plan changes keeps its last-good binding until the new slot is ready,
// then moves to it in one map write. A pod given with an empty plan
// (incomplete input, see Controller.PodPlans) keeps its current binding. A pod
// that is not given, or whose plan has no policy of this section, is unbound
// (an authoritative removal).
//
// A pod binding and the container bindings under it: the gadgets look up the
// task's own cgroup first, then its parents (binding_lookup in
// pkg/ebpf/gadgets/common/bindings.h), so the nearest bound cgroup decides. A
// container is judged by the pod binding from its first command until its own
// binding exists, then by its own binding. Both have the same slot, because
// the pod plan is the plan of every container. Unbinding the pod leaves the
// container bindings; unbinding a container makes its remaining tasks fall
// back to the pod binding, which has the same policies. A replacement keeps
// the pod bindings (replaceInstance with withPods).
func (b *nodeOwner[C]) BindPods(ctx context.Context, pods []sandboxpolicy.PodBinding) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("%s backend is closed", b.section.name)
	}
	ready := b.instance != nil && b.instance.Ready() == nil
	wanted := make(map[types.UID]sandboxpolicy.PodBinding, len(pods))
	for _, p := range pods {
		wanted[p.PodUID] = p
	}
	var errs []error
	for uid, current := range b.pods {
		next, ok := wanted[uid]
		if ok && next.CgroupID == current.pod.CgroupID && next.CgroupPath == current.pod.CgroupPath {
			// An empty plan (incomplete input) keeps the binding; a plan
			// with policies of this section keeps it until the pod moves
			// below. A plan with no policy of this section removes it.
			if _, policies := b.section.combination(next.Plan); len(next.Plan.Policies) == 0 || len(policies) > 0 {
				continue
			}
		}
		// Not wanted, or a new cgroup for the pod: remove the old identity.
		// An instance that is not ready protects nothing.
		if ready {
			if err := b.instance.Unbind(b.nativePod(current.pod, 0).Container); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(b.pods, uid)
	}
	for uid, p := range wanted {
		combination, policies := b.section.combination(p.Plan)
		current := b.pods[uid]
		if len(policies) == 0 || current != nil && current.combination == combination {
			continue
		}
		slot, ok := b.slots[combination]
		if !ok || !ready {
			continue
		}
		if err := b.instance.Bind(b.nativePod(p, slot)); err != nil {
			errs = append(errs, err)
			continue
		}
		b.pods[uid] = &podBinding{pod: p, combination: combination}
		logger.L().Info("sandbox "+b.section.name+" pod bind", helpers.String("namespace", p.Namespace), helpers.String("pod", p.PodName),
			helpers.String("cgroup", fmt.Sprint(p.CgroupID)), helpers.Int("slot", int(slot)))
	}
	return errors.Join(append(errs, b.retire(ctx))...)
}

// replaceInstance starts a candidate with every combination in use or prepared
// (plus extra), binds every container (plus next, under nextKey) and, with
// withPods, every pod cgroup, and only then stops the old instance. Without
// withPods, the pod bindings are dropped. On failure the old instance and
// state stay.
func (b *nodeOwner[C]) replaceInstance(ctx context.Context, prepared, extra map[string][]sandboxpolicy.CompiledPolicy, nextKey identity, next *nodeBinding, withPods bool) error {
	pods := b.pods
	if !withPods {
		pods = map[types.UID]*podBinding{}
	}
	bindings := map[identity]*nodeBinding{}
	for k, v := range b.bindings {
		bindings[k] = v
	}
	if next != nil {
		bindings[nextKey] = next
	}
	wanted := b.wanted(prepared, extra, bindings, pods)
	slots, policies := slotList(wanted)
	compiled, err := b.section.compile(b.generation+1, policies)
	if err != nil {
		return err
	}
	// Before start: the candidate can report verdicts before it is ready.
	b.remember(b.generation+1, policies)
	var initial []enforcement.Binding
	for _, v := range bindings {
		initial = append(initial, enforcement.Binding{Container: native(v.binding), Slot: slots[v.combination]})
	}
	for _, p := range pods {
		initial = append(initial, b.nativePod(p.pod, slots[p.combination]))
	}
	b.generation++
	candidate, err := b.section.start(ctx, fmt.Sprintf("%s-%s-%d", b.prefix, b.section.name, b.generation), compiled, initial)
	b.recordStart(err)
	if err != nil {
		b.forget(b.generation) // start cleaned up: no more events
		return err
	}
	b.track(candidate, b.generation)
	if err = candidate.Ready(); err != nil {
		if stopErr := candidate.Stop(ctx); stopErr != nil {
			b.retiring = append(b.retiring, candidate) // retried by retire
			return errors.Join(err, stopErr)
		}
		b.untrack(candidate)
		return err
	}
	if b.instance != nil {
		b.retiring = append(b.retiring, b.instance)
	}
	b.instance, b.slots, b.combinations, b.bindings, b.prepared, b.pods = candidate, slots, wanted, bindings, prepared, pods
	b.stats.Replacements++
	logger.L().Info("sandbox "+b.section.name+" instance ready", helpers.Int("generation", int(b.generation)),
		helpers.Int("slots", len(slots)), helpers.Int("prepared", len(prepared)), helpers.Int("containers", len(bindings)), helpers.Int("pods", len(pods)))
	return nil
}

// wanted returns every combination of the prepared set, extra, the given
// container bindings and the given pod bindings.
func (b *nodeOwner[C]) wanted(prepared, extra map[string][]sandboxpolicy.CompiledPolicy, bindings map[identity]*nodeBinding, pods map[types.UID]*podBinding) map[string][]sandboxpolicy.CompiledPolicy {
	wanted := map[string][]sandboxpolicy.CompiledPolicy{}
	for c, p := range prepared {
		wanted[c] = p
	}
	for c, p := range extra {
		wanted[c] = p
	}
	for _, v := range bindings {
		if _, ok := wanted[v.combination]; !ok {
			wanted[v.combination] = b.combinations[v.combination]
		}
	}
	for _, p := range pods {
		if _, ok := wanted[p.combination]; !ok {
			wanted[p.combination] = b.combinations[p.combination]
		}
	}
	return wanted
}

// slotList gives each combination a slot, in key order.
func slotList(wanted map[string][]sandboxpolicy.CompiledPolicy) (map[string]uint32, [][]sandboxpolicy.CompiledPolicy) {
	keys := make([]string, 0, len(wanted))
	for c := range wanted {
		keys = append(keys, c)
	}
	sort.Strings(keys)
	slots := map[string]uint32{}
	policies := make([][]sandboxpolicy.CompiledPolicy, len(keys))
	for i, c := range keys {
		slots[c] = uint32(i)
		policies[i] = wanted[c]
	}
	return slots, policies
}

// retire stops replaced instances and keeps the ones that still fail.
func (b *nodeOwner[C]) retire(ctx context.Context) error {
	var kept []NodeInstance
	var errs []error
	for _, i := range b.retiring {
		// The maps go with the instance: read the counters before Stop.
		last, readErr := counters(i)
		if err := i.Stop(ctx); err != nil {
			kept = append(kept, i)
			errs = append(errs, err)
			continue
		}
		if readErr != nil {
			b.retiredUnavailable++
		} else {
			addCounters(&b.retired, last)
		}
		b.untrack(i)
	}
	b.retiring = kept
	return errors.Join(errs...)
}

func (b *nodeOwner[C]) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.instance != nil {
		b.retiring = append(b.retiring, b.instance)
		b.instance = nil
	}
	var errs []error
	for _, v := range b.bindings {
		errs = append(errs, v.close())
	}
	b.bindings = map[identity]*nodeBinding{}
	b.pods = map[types.UID]*podBinding{}
	return errors.Join(append(errs, b.retire(ctx))...)
}
