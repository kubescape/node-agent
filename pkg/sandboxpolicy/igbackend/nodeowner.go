package igbackend

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"k8s.io/apimachinery/pkg/types"
)

// NodeInstance is one running node-wide gadget instance. It is long-lived: a
// new combination is published into a free slot in place (no reload).
type NodeInstance interface {
	Ready() error
	// SlotHealth fails when the instance counted a fault in the slot (for
	// privilege: a task of an enforcing slot may be untracked).
	SlotHealth(slot uint32) error
	Bind(enforcement.Binding) error
	Unbind(enforcement.ContainerIdentity) error
	Stop(context.Context) error
	// Publish writes the section's compiled policy of one combination (one
	// slot, from nodeSection.compile) into slot. On error the slot keeps its
	// last-good policy.
	Publish(slot uint32, compiled any) error
	// Free retires a slot that no binding uses; Available reports whether a
	// slot can take a new publication (a freed slot waits a quarantine).
	Free(slot uint32) error
	Available(slot uint32) bool
	// Heal arms the bound tasks of the slot again (and of every slot after
	// node faults) and restarts the fault count. No reload.
	Heal(slot uint32) error
	// Collect deletes the buffers whose quarantine ended.
	Collect() error
}

// NodeStats counts how container binds found their policy slot.
type NodeStats struct {
	// Prepared: the slot already existed (created when the pod was scheduled,
	// or used by another container), so the bind was a live map write.
	Prepared uint64
	// Replaced: the slot was missing: it was published into the running
	// instance, or an instance was started with it.
	Replaced uint64
	// Publications counts the combinations published into a running
	// instance (no reload).
	Publications uint64
	// Replacements counts every node instance start: the first one, and a
	// replacement of an instance that is not ready. A policy change never
	// replaces the instance.
	Replacements uint64
}

// nodeSection is what a node owner needs from one policy section. C is the
// section's compiled policy.
type nodeSection[C any] struct {
	name string
	// combination returns the section's policies of a plan, sorted, and
	// their key. Containers with the same key share a slot.
	combination func(sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy)
	// compile compiles one instance: slot i holds the policies slots[i]. A
	// publication compiles one combination alone (one slot).
	compile func(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) (C, error)
	// slots is the number of slots of an instance (the gadget's limit).
	slots uint32
	// inPlace: the gadget publishes slots into a running instance
	// (NodeInstance.Publish). Without it a missing combination replaces the
	// instance (a section not moved to the publish model yet).
	inPlace bool
	start   func(ctx context.Context, id string, compiled C, bindings []enforcement.Binding) (NodeInstance, error)
	// startEmpty makes Prepare start an instance with no slot when none
	// runs, so the first container does not wait for the slow first gadget
	// load.
	startEmpty bool
	// arming: a bind arms the tasks already in the cgroup (privilege). A pod
	// binding then skips the arming (see nativePod). Only arming faults (lost
	// task marks) heal with a new instance, which arms the running tasks
	// again; the other slot faults (a task outside a Strict exact scope) stay
	// until their cause ends, and a reload cannot fix them.
	arming bool
}

// reservation is a combination prepared for one binding (PrepareReplace).
type reservation struct {
	combination string
	policies    []sandboxpolicy.CompiledPolicy
}

type nodeBinding struct {
	binding     sandboxpolicy.Binding
	revision    string
	combination string
	// lease pins the live container identity while it is bound (nil when the
	// backend has no validator).
	lease Lease
	// pendingUnbind: withdrawn while the instance was not ready. Its
	// programs may still enforce, so the record stays until the unbind
	// succeeds or a new instance (which never binds it) replaces the old one.
	pendingUnbind bool
	// bindFailed: a later bind of this container failed, and the kernel may
	// hold the container in another slot: its protection is unconfirmed until
	// a bind succeeds.
	bindFailed bool
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
	// confirmed: the binding judges every task of the pod's containers. With
	// arming, only when it was bound in the current instance before any
	// container of the pod started (a pod binding arms no running task).
	confirmed bool
}

// podRuntime is the runtime name of a pod cgroup identity in the bindings
// controller. No container runtime has this name.
const podRuntime = "kubernetes-pod"

// nativePod returns the bindings controller identity of a pod cgroup. It
// covers the container cgroups below it (Subtree). With arming, it admits the
// runtime helper exemption for the OCI hooks that run before a container's
// workload (RuntimeHelpers), and the tasks already in it are not armed: runc
// init of a container being created can be there. A section without arming
// has nothing to skip.
func (b *nodeOwner[C]) nativePod(p sandboxpolicy.PodBinding, slot uint32) enforcement.Binding {
	return enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: string(p.PodUID), CgroupID: p.CgroupID, CgroupPath: p.CgroupPath}, Slot: slot,
		Subtree: true, RuntimeHelpers: b.section.arming, SkipArming: b.section.arming}
}

// podConfirmed reports whether a pod binding made now judges every task of
// the pod (see podBinding.confirmed).
func (b *nodeOwner[C]) podConfirmed(p sandboxpolicy.PodBinding) bool {
	return !b.section.arming || !p.ContainersStarted
}

// emptyRetry is the shortest time between two starts of an instance with no
// slot: each start is a slow gadget load on the refresh loop.
const emptyRetry = 30 * time.Second

// healRetry is the shortest time between two new instances started only to
// heal tracking faults. Faults recur under memory pressure; a gadget reload on
// every reconcile would add load then. The binding stays unconfirmed meanwhile.
const healRetry = 30 * time.Second

// nodeHealRetry replaces healRetry when only node faults fail the health: a
// new instance cannot fix a cause that persists, and each reload unconfirms
// the pod bindings of running pods.
const nodeHealRetry = 10 * time.Minute

// prepareHeadroom is the number of slots Prepare leaves free for the
// combinations of containers that start (a pod plan Prepare did not see).
const prepareHeadroom = 4

// errNoFreeSlot: every slot of the instance holds a combination.
var errNoFreeSlot = errors.New("no free policy slot")

// ErrNodeFaultsOnly marks a slot health error caused only by node tracking
// faults (see NodeInstance.SlotHealth).
var ErrNodeFaultsOnly = errors.New("node tracking faults")

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
	// reserved holds, per binding, the combination of its last successful
	// PrepareReplace, kept (in every replacement, and from being freed)
	// until that binding's Replace or Withdraw consumes it.
	reserved map[identity]reservation
	retiring []NodeInstance
	stats    NodeStats
	closed   bool
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
	// content maps a combination to the generation whose table holds its
	// slot (the instance start, or its publication); publications lists the
	// publication generations of each instance, forgotten with it (under mu).
	content      map[string]uint64
	publications map[NodeInstance][]uint64
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
	defer delete(b.reserved, k) // consumed, whatever the outcome
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
	if current != nil && current.revision == plan.Revision && current.combination == combination && health == nil && !current.pendingUnbind {
		result.Committed = true
		return result, errors.Join(b.sweep(), b.retire(ctx))
	}
	// reload: heal with a new instance (see the heal below).
	reload := false
	if slot, ok := b.slots[combination]; ok && current != nil && current.revision == plan.Revision && current.combination == combination &&
		!current.pendingUnbind && b.instance.Ready() == nil && current.check() == nil {
		if !b.section.arming {
			// A slot fault without arming (a task outside a Strict
			// exact scope): it stays until its cause ends.
			return result, health
		}
		// Only tracking faults: heal in place (arm the slot's tasks again),
		// at most every healRetry. Node faults alone come from any
		// workload on the node and may persist, so they heal at most every
		// nodeHealRetry.
		retry := healRetry
		if errors.Is(health, ErrNodeFaultsOnly) {
			retry = nodeHealRetry
		}
		if time.Since(b.lastHeal) < retry {
			return result, health
		}
		b.lastHeal = time.Now()
		if b.section.inPlace {
			err := b.instance.Heal(slot)
			switch {
			case errors.Is(err, enforcement.ErrNotHealable):
				// Tasks a heal cannot arm (a pod binding never arms):
				// a new instance heals, as without in-place publishing.
				reload = true
			case err != nil:
				return result, errors.Join(health, err)
			default:
				if health = b.health(current); health != nil {
					return result, health
				}
				result.Committed, result.ProtectionUnconfirmed = true, false
				return result, b.retire(ctx)
			}
		}
		// Without in-place publishing a new instance heals: it arms the
		// running tasks again (below).
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
		errs = append(errs, b.sweep(), b.retire(ctx))
		// A slot with faults stays unconfirmed: a bind does not heal it.
		return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: b.health(next) != nil}, errors.Join(errs...)
	}
	fail := func(err error) (sandboxpolicy.ReplaceResult, error) {
		if next.lease != nil && (current == nil || next.lease != current.lease) {
			err = errors.Join(err, next.close())
		}
		return result, err
	}
	if slot, ok := b.slots[combination]; ok && !b.section.inPlace && b.instance != nil && health == nil {
		if err := b.instance.Bind(enforcement.Binding{Container: native(binding), Slot: slot}); err != nil {
			return fail(err)
		}
		b.refresh(combination, policies)
		if current == nil {
			b.stats.Prepared++
			b.logBind(binding, "prepared")
		}
		b.bindings[k] = next
		return commit()
	}
	if b.section.inPlace && !reload && b.instance != nil && b.instance.Ready() == nil {
		// The running instance takes a missing combination in place. On
		// a failed publish the container keeps its last-good slot.
		_, existed := b.slots[combination]
		slot, err := b.publish(combination, policies)
		if errors.Is(err, errNoFreeSlot) {
			// A container comes before speculation: drop the slots that
			// only Prepare wanted. They are reusable after the quarantine,
			// so a retry binds.
			b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
			err = errors.Join(err, b.sweep())
		}
		if err != nil {
			return fail(err)
		}
		if err := b.instance.Bind(enforcement.Binding{Container: native(binding), Slot: slot}); err != nil {
			if current != nil && current.combination != combination {
				// A failed move can leave the kernel on either slot.
				current.bindFailed = true
			}
			return fail(err)
		}
		b.refresh(combination, policies)
		if current == nil && existed {
			b.stats.Prepared++
			b.logBind(binding, "prepared")
		} else if current == nil {
			b.stats.Replaced++
			b.logBind(binding, "published")
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

// refresh records the newest identities (generation, revision) of a
// combination whose content is unchanged. The running instance keeps its slot,
// so without this its verdicts would name the generation it started with. It
// runs under mu.
func (b *nodeOwner[C]) refresh(combination string, policies []sandboxpolicy.CompiledPolicy) {
	slot, ok := b.slots[combination]
	if !ok {
		return
	}
	b.combinations[combination] = policies
	b.tablesMu.Lock()
	defer b.tablesMu.Unlock()
	if table, ok := b.tables[b.content[combination]]; ok && int(slot) < len(table) {
		table[slot] = append([]sandboxpolicy.CompiledPolicy(nil), policies...)
	}
}

func (b *nodeOwner[C]) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	delete(b.reserved, k)
	current := b.bindings[k]
	if current == nil {
		return sandboxpolicy.WithdrawResult{Committed: true}, b.retire(ctx)
	}
	// An instance that is not ready may still run its programs: keep the
	// record as pending and let the caller retry.
	if b.instance != nil {
		if err := b.instance.Ready(); err != nil {
			current.pendingUnbind = true
			// A new instance never binds a pending record; replace the
			// instance that is not ready, at most every healRetry, so a
			// pending withdraw cannot wait forever.
			if time.Since(b.lastHeal) < healRetry {
				return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, fmt.Errorf("%s unbind pending: %w", b.section.name, err)
			}
			b.lastHeal = time.Now()
			if rerr := b.replaceInstance(ctx, b.prepared, nil, identity{}, nil, true); rerr != nil {
				return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, errors.Join(fmt.Errorf("%s unbind pending: %w", b.section.name, err), rerr)
			}
			// replaceInstance dropped the record and closed its lease.
			return sandboxpolicy.WithdrawResult{Committed: true}, b.retire(ctx)
		}
		if err := b.instance.Unbind(native(binding)); err != nil {
			current.pendingUnbind = true
			return sandboxpolicy.WithdrawResult{ProtectionUnconfirmed: true}, err
		}
	}
	delete(b.bindings, k)
	return sandboxpolicy.WithdrawResult{Committed: true}, errors.Join(current.close(), b.sweep(), b.retire(ctx))
}

// PrepareReplace makes sure the plan's combination has a slot in a ready
// instance, replacing the node instance if needed, and binds nothing
// (sandboxpolicy.ReplacePreparer). The slot stays reserved in later
// replacements until a Replace consumes it, so the Replace that follows is
// normally a live map write.
func (b *nodeOwner[C]) PrepareReplace(ctx context.Context, binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("%s backend is closed", b.section.name)
	}
	combination, policies := b.section.combination(plan)
	if len(policies) == 0 {
		return fmt.Errorf("plan has no %s section", b.section.name)
	}
	// Reserved only when the slot exists: a combination that does not fit
	// must never be carried into other workloads' replacements.
	k := key(binding)
	delete(b.reserved, k)
	reserve := func() {
		if b.reserved == nil {
			b.reserved = map[identity]reservation{}
		}
		b.reserved[k] = reservation{combination, policies}
	}
	extra := map[string][]sandboxpolicy.CompiledPolicy{combination: policies}
	if _, ok := b.slots[combination]; ok && !b.section.inPlace && b.instance != nil && b.instance.Ready() == nil {
		reserve()
		return nil
	}
	if b.section.inPlace && b.instance != nil && b.instance.Ready() == nil {
		// Published in place when missing; no reload. A container comes
		// before speculation: with no free slot, the prepared-only slots
		// are dropped and a retry fits.
		_, err := b.publish(combination, policies)
		if errors.Is(err, errNoFreeSlot) {
			b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
			err = errors.Join(err, b.sweep())
		}
		if err != nil {
			return errors.Join(err, b.retire(ctx))
		}
		reserve()
		return b.retire(ctx)
	}
	err := b.replaceInstance(ctx, b.prepared, extra, identity{}, nil, true)
	if err != nil && len(b.prepared) > 0 {
		err = b.replaceInstance(ctx, nil, extra, identity{}, nil, true)
	}
	if err == nil {
		reserve()
	}
	return errors.Join(err, b.retire(ctx))
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
	if p.bindFailed {
		return fmt.Errorf("%s: the last bind of this container failed", b.section.name)
	}
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
	if b.section.inPlace && b.instance != nil && b.instance.Ready() == nil {
		// The running instance takes each missing combination in place,
		// in order (pod plans first); one that does not fit (no free slot,
		// a capacity limit) is left out. Unused slots are freed first.
		b.prepared = prepared
		errs := []error{b.sweep()}
		unfit := 0
		for _, c := range order {
			_, exists := b.slots[c]
			if !exists && len(b.slots) >= int(b.section.slots)-prepareHeadroom {
				delete(b.prepared, c) // keep slots free for containers
				unfit++
				continue
			}
			if _, err := b.publish(c, prepared[c]); err != nil {
				if !errors.Is(err, errNoFreeSlot) {
					// Not capacity: a map or compile failure. Like a
					// combination that does not fit, it is not an
					// error of Prepare, but it is logged.
					logger.L().Warning("sandbox "+b.section.name+" prepare: publish failed", helpers.Error(err))
				}
				delete(b.prepared, c)
				unfit++
			}
		}
		b.logUnfit(len(b.prepared), unfit)
		return errors.Join(append(errs, b.retire(ctx))...)
	}
	if b.missing(prepared) {
		var unfit int
		prepared, unfit = b.fit(order, prepared)
		b.logUnfit(len(prepared), unfit)
	}
	// An instance that is not ready protects nothing that can be confirmed,
	// and it holds pending withdrawals: replace it, at most every healRetry.
	heal := b.instance != nil && b.instance.Ready() != nil && time.Since(b.lastHeal) >= healRetry
	if heal {
		b.lastHeal = time.Now()
	}
	if !heal && !b.missing(prepared) {
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

// logUnfit logs the prepared combinations left out, when their number changes.
func (b *nodeOwner[C]) logUnfit(prepared, unfit int) {
	if unfit == b.unfit {
		return
	}
	b.unfit = unfit
	if unfit > 0 {
		logger.L().Warning("sandbox "+b.section.name+" prepare: policy combinations do not fit in the instance, not prepared",
			helpers.Int("prepared", prepared), helpers.Int("notPrepared", unfit))
	}
}

// publish returns the slot of a combination. A combination with no slot is
// compiled alone and published into a free slot of the running instance, in
// place: no reload, no second instance. Each publication has its own
// generation (the verdicts carry it). Runs under mu with a ready instance.
func (b *nodeOwner[C]) publish(combination string, policies []sandboxpolicy.CompiledPolicy) (uint32, error) {
	if slot, ok := b.slots[combination]; ok {
		return slot, nil
	}
	used := make(map[uint32]bool, len(b.slots))
	for _, s := range b.slots {
		used[s] = true
	}
	compiled, err := b.section.compile(b.generation+1, [][]sandboxpolicy.CompiledPolicy{policies})
	if err != nil {
		return 0, err
	}
	for slot := uint32(0); slot < b.section.slots; slot++ {
		if used[slot] || !b.instance.Available(slot) {
			continue
		}
		err := b.publishInto(slot, combination, policies, compiled)
		if errors.Is(err, enforcement.ErrSlotBusy) {
			continue // a buffer whose delete failed: try the next slot
		}
		return slot, err
	}
	return 0, fmt.Errorf("%s: %w (%d in use)", b.section.name, errNoFreeSlot, len(b.slots))
}

// publishInto publishes a compiled combination into one free slot.
func (b *nodeOwner[C]) publishInto(slot uint32, combination string, policies []sandboxpolicy.CompiledPolicy, compiled C) error {
	// Before the flip: the slot can report verdicts at once.
	table := make([][]sandboxpolicy.CompiledPolicy, slot+1)
	table[slot] = policies
	b.remember(b.generation+1, table)
	if err := b.instance.Publish(slot, compiled); err != nil {
		b.forget(b.generation + 1)
		return err
	}
	b.generation++
	if b.content == nil {
		b.content = map[string]uint64{}
	}
	if b.publications == nil {
		b.publications = map[NodeInstance][]uint64{}
	}
	b.content[combination] = b.generation
	b.publications[b.instance] = append(b.publications[b.instance], b.generation)
	b.slots[combination], b.combinations[combination] = slot, policies
	b.stats.Publications++
	logger.L().Info("sandbox "+b.section.name+" publish", helpers.Int("slot", int(slot)), helpers.Int("generation", int(b.generation)))
	return nil
}

// sweep frees the slots of the combinations no binding, pod, prepared or
// reserved plan uses, and deletes the buffers whose quarantine ended. A freed
// slot is reused only after its quarantine. Runs under mu.
func (b *nodeOwner[C]) sweep() error {
	if !b.section.inPlace || b.instance == nil || b.instance.Ready() != nil {
		return nil // a frozen instance drops unused slots at its replacement
	}
	wanted := b.wanted(b.prepared, nil, b.bindings, b.pods)
	var errs []error
	for c, slot := range b.slots {
		if _, ok := wanted[c]; ok {
			continue
		}
		if err := b.instance.Free(slot); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(b.slots, c)
		delete(b.combinations, c)
		// An unbound slot reports no more verdicts: drop the table of its
		// publication (an instance start's table holds several slots).
		if g, ok := b.content[c]; ok && g != b.generations[b.instance] {
			b.forget(g)
			b.publications[b.instance] = slices.DeleteFunc(b.publications[b.instance], func(p uint64) bool { return p == g })
		}
		delete(b.content, c)
	}
	return errors.Join(append(errs, b.instance.Collect())...)
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
		// Keep the headroom for containers (see prepareHeadroom).
		if b.section.inPlace && len(wanted) > int(b.section.slots)-prepareHeadroom {
			return false
		}
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

// BoundPodPlans returns the plans of the pod cgroups bound now (see
// sandboxpolicy.PodPlanReporter). While the instance is not ready, every pod
// plan is faulted: its protection cannot be confirmed.
func (b *nodeOwner[C]) BoundPodPlans() (confirmed, faulted []sandboxpolicy.Plan) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil
	}
	// While the instance is not ready, every pod plan is faulted.
	ready := b.instance != nil && b.instance.Ready() == nil
	for _, p := range b.pods {
		slot, ok := b.slots[p.combination]
		switch {
		case !ready || !ok || b.instance.SlotHealth(slot) != nil:
			faulted = append(faulted, p.pod.Plan)
		case p.confirmed:
			confirmed = append(confirmed, p.pod.Plan)
		}
	}
	return confirmed, faulted
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
		if len(policies) == 0 {
			continue
		}
		if current != nil && current.combination == combination {
			// The same enforcement: keep the binding, its cgroup identity
			// and its confirmation; record the newer plan (its generation)
			// and the containers' state for status and verdicts.
			current.pod.Plan = p.Plan
			current.pod.ContainersStarted = current.pod.ContainersStarted || p.ContainersStarted
			b.refresh(combination, policies)
			continue
		}
		// With arming, a pod binding arms no running task: a pod whose
		// containers started gets no new pod binding and relies on its
		// container bindings. A bound pod whose plan changed moves to the
		// new slot, so a restarted container is never judged by a superseded
		// plan, but the move is not confirmed.
		if !b.podConfirmed(p) && current == nil {
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
		b.pods[uid] = &podBinding{pod: p, combination: combination, confirmed: b.podConfirmed(p)}
		logger.L().Info("sandbox "+b.section.name+" pod bind", helpers.String("namespace", p.Namespace), helpers.String("pod", p.PodName),
			helpers.String("cgroup", fmt.Sprint(p.CgroupID)), helpers.Int("slot", int(slot)))
	}
	return errors.Join(append(errs, b.sweep(), b.retire(ctx))...)
}

// replaceInstance starts a candidate with every combination in use or prepared
// (plus extra), binds every container (plus next, under nextKey) and, with
// withPods, every pod cgroup, and only then stops the old instance. Without
// withPods, the pod bindings are dropped. On failure the old instance and
// state stay.
func (b *nodeOwner[C]) replaceInstance(ctx context.Context, prepared, extra map[string][]sandboxpolicy.CompiledPolicy, nextKey identity, next *nodeBinding, withPods bool) error {
	// With arming, a new instance arms no task under a pod binding, so a
	// carried pod binding is confirmed only while no container of the pod has
	// started.
	pods := map[types.UID]*podBinding{}
	if withPods {
		for uid, p := range b.pods {
			pods[uid] = &podBinding{pod: p.pod, combination: p.combination, confirmed: b.podConfirmed(p.pod)}
		}
	}
	// A pending unbind is not carried: the new instance never binds it, and
	// the old instance stops after the switch.
	bindings := map[identity]*nodeBinding{}
	var withdrawn []*nodeBinding
	for k, v := range b.bindings {
		if v.pendingUnbind {
			// Under nextKey, next replaces the record, and Replace's commit
			// closes the old lease when next does not reuse it.
			if next == nil || k != nextKey {
				withdrawn = append(withdrawn, v)
			}
			continue
		}
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
	b.content = map[string]uint64{}
	for c := range slots {
		b.content[c] = b.generation
	}
	b.stats.Replacements++
	logger.L().Info("sandbox "+b.section.name+" instance ready", helpers.Int("generation", int(b.generation)),
		helpers.Int("slots", len(slots)), helpers.Int("prepared", len(prepared)), helpers.Int("containers", len(bindings)), helpers.Int("pods", len(pods)))
	var errs []error
	for _, v := range withdrawn {
		errs = append(errs, v.close())
	}
	return errors.Join(errs...)
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
	for _, r := range b.reserved {
		wanted[r.combination] = r.policies
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
