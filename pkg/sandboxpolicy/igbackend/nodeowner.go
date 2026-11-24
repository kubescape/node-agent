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
	// Rebind hands the cgroup of old's active binding over to next with one
	// map write; the slot gate applies to next first, as for Bind.
	Rebind(old enforcement.ContainerIdentity, next enforcement.Binding) error
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
	// PublishedSlots returns the published slots of the section's state,
	// with their generation (an instance re-opens the pinned state).
	PublishedSlots() map[uint32]uint64
	// DropAdopted deletes the kernel bindings of the state that no Bind
	// took over, except those keep accepts; it returns how many remain.
	DropAdopted(keep func(cgroup uint64, slot uint32, strict bool) bool) (int, error)
	// AdoptedBindings counts those bindings per slot.
	AdoptedBindings() map[uint32]int
	// ResetFaults takes the current fault counts of the state as the
	// baseline, so the faults an earlier instance counted do not fail the
	// health of this one.
	ResetFaults() error
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
	// resetState removes the section's pinned state before the first
	// start (removePinnedMaps with the section's prefix).
	resetState func() error
	// mapPrefix is the prefix of the section's pinned state maps (pin.h),
	// and image names the gadget image (name, digest): a pinned state is
	// restored only into the same image and layout. image is nil when the
	// engine cannot tell (tests).
	mapPrefix string
	image     func(ctx context.Context) (name, digest string, err error)
	start     func(ctx context.Context, id string, compiled C, bindings []enforcement.Binding) (NodeInstance, error)
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
	at          time.Time
}

// reservationTTL bounds a reservation whose Replace never came (a later
// section failed and the container went away): it stops pinning its slot.
const reservationTTL = 10 * time.Minute

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
	// bindPending: the pod's cgroup moved, the old one was unbound and the
	// bind of the new one failed. Nothing is bound; the next call retries
	// (whatever its containers' state), and status reports it faulted.
	bindPending bool
	// pendingUnbind: no longer wanted while the instance was not ready. It
	// is still bound there; the next call on a ready instance unbinds it.
	pendingUnbind bool
	// pendingMark: the pod cgroup carries the start gate's pending mark
	// (MarkPod): a binding to enforcement.PendingSlot with the class strict,
	// not yet the slot of combination. policies are combination's policies
	// (b.combinations may not have it yet). With bindPending, the mark's
	// write into a new instance failed: the kernel entry is not known.
	pendingMark bool
	strict      bool
	policies    []sandboxpolicy.CompiledPolicy
	// sequenced: written by the start gate (MarkPod); its writes are
	// ordered by lastSeq, the newest sequence that wrote it (see
	// sandboxpolicy.Seq). Other records follow main's rules.
	sequenced bool
	lastSeq   sandboxpolicy.Seq
	// released: ReleasePod removed the pod while the instance was not
	// ready. The record only waits for its unbind: no call binds, marks or
	// takes it back.
	released bool
}

// admits reports whether a write at seq applies to the record (see
// sandboxpolicy.Seq.Admits). A record main wrote admits every write. A
// sequenced one admits a write without a sequence (seq nil, main's BindPods)
// only when it raises the record (Audit to Strict, a removal taken back),
// which cannot fail open; never a loosening or another plan change.
func (p *podBinding) admits(seq *sandboxpolicy.Seq, loosen, raise bool) bool {
	if !p.sequenced {
		return true
	}
	if seq == nil {
		return raise && !loosen
	}
	return seq.Admits(p.lastSeq, loosen)
}

// advance keeps the newest sequence that wrote the record: it never lowers
// lastSeq (a sequence-neutral bind at an older sequence keeps it).
func (p *podBinding) advance(seq *sandboxpolicy.Seq) {
	if p.sequenced && seq != nil && seq.Compare(p.lastSeq) == sandboxpolicy.SeqNewer {
		p.lastSeq = *seq
	}
}

// takesBack reports whether the input p takes back the pending removal of
// start gate record current, together with the plan change that comes with
// it (S2 review v5, L3): a removal is taken back only when the whole write
// is admitted. Runs under mu.
func (b *nodeOwner[C]) takesBack(current *podBinding, p sandboxpolicy.PodBinding, seq *sandboxpolicy.Seq) bool {
	if !current.admits(seq, false, true) {
		return false
	}
	combination, policies := b.section.combination(p.Plan)
	if !current.sequenced || len(policies) == 0 ||
		(current.combination == combination && p.CgroupID == current.pod.CgroupID && p.CgroupPath == current.pod.CgroupPath) {
		return true
	}
	was, strict := b.class(current), strictPolicies(policies)
	return current.admits(seq, was && !strict, !was && strict)
}

// class is the record's class: its own for a pending mark, else its plan's.
func (b *nodeOwner[C]) class(p *podBinding) bool {
	if p.pendingMark {
		return p.strict
	}
	policies, known := b.combinations[p.combination]
	return !known || strictPolicies(policies)
}

// errStale is ErrStaleSequence for one pod of the section.
func (b *nodeOwner[C]) errStale(p sandboxpolicy.PodBinding) error {
	return fmt.Errorf("%s pod %s/%s: %w", b.section.name, p.Namespace, p.PodName, sandboxpolicy.ErrStaleSequence)
}

// podRuntime is the runtime name of a pod cgroup identity in the bindings
// controller. No container runtime has this name.
const podRuntime = "kubernetes-pod"

// nativePod returns the bindings controller identity of a pod cgroup. It
// covers the container cgroups below it (Subtree). With arming, the tasks
// already in it are not armed: runc init of a container being created can be
// there. With arming and the host operator's consent (helpers, off by
// default), it admits the runtime helper exemption for the OCI hooks that run
// before a container's workload (RuntimeHelpers); without it those hooks are
// judged like the workload. A section without arming has nothing to skip.
func (b *nodeOwner[C]) nativePod(p sandboxpolicy.PodBinding, slot uint32) enforcement.Binding {
	return enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: string(p.PodUID), CgroupID: p.CgroupID, CgroupPath: p.CgroupPath}, Slot: slot,
		Subtree: true, RuntimeHelpers: b.section.arming && b.helpers, SkipArming: b.section.arming}
}

// nativeMark is the pending mark of a pod record: its pod cgroup identity on
// enforcement.PendingSlot, with the record's class.
func (b *nodeOwner[C]) nativeMark(p *podBinding) enforcement.Binding {
	mark := b.nativePod(p.pod, enforcement.PendingSlot)
	mark.Strict = p.strict
	return mark
}

// nativeOf is the kernel binding a pod record stands for: its mark while
// pending, else its slot in slots.
func (b *nodeOwner[C]) nativeOf(p *podBinding, slots map[string]uint32) enforcement.Binding {
	if p.pendingMark {
		return b.nativeMark(p)
	}
	return b.nativePod(p.pod, slots[p.combination])
}

// SetRuntimeHelperExemption records the host operator's consent to the
// runtime helper exemption on pod cgroup bindings of an arming section
// (default off). Call it
// before the first bind. Without it, OCI hooks that run inside a pod cgroup
// are judged like the workload; a hook that a Strict policy denies then fails
// the container start.
func (b *nodeOwner[C]) SetRuntimeHelperExemption(on bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.helpers = on
}

// RuntimeHelperStatus reports the runtime helper exemption: whether the
// operator enabled it, the plans of the pod bindings that carry it, and the
// execs it exempted on this node (from the gadget's witness; err when it
// cannot be read: unknown, never zero).
func (b *nodeOwner[C]) RuntimeHelperStatus() (enabled bool, plans []sandboxpolicy.Plan, exempt uint64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.helpers || !b.section.arming || b.closed {
		return false, nil, 0, nil
	}
	for _, p := range b.pods {
		plans = append(plans, p.pod.Plan)
	}
	w, ok := b.instance.(interface {
		NodeCounters() (enforcement.NodeCounters, error)
	})
	if !ok || b.instance == nil {
		return true, plans, 0, fmt.Errorf("no running %s instance reports exempted execs", b.section.name)
	}
	c, err := w.NodeCounters()
	return true, plans, c.ExemptExecs, err
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
// changed policy) is published into a free slot in place (inPlace), or, for a
// section without in-place publishing, replaces the node instance: start the
// candidate with every slot in use, wait until it is ready with every
// container bound, then stop the old instance. Both enforce during the
// overlap. Unused slots are freed by the sweep (inPlace) or dropped at the
// next replacement.
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
	// started: an instance started once (the first start resets the
	// pinned state, unless restart survival restored it).
	started bool
	// pins is the restart survival state (nil: off). See restart.go.
	pins *pinning
	// survivalOff: restart survival is off for this run because the boot
	// id or the pinned sets could not be read; the sets are kept.
	survivalOff error
	// orphans are the published slots of the state that no combination of
	// the owner holds (an earlier instance published them); the sweep frees
	// them.
	orphans map[uint32]bool
	// dropPending: the kernel bindings of the state that no bind took over
	// are dropped (by the sweep) once every container is bound.
	dropPending bool
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
	// capacity: the last start was refused because a hook's trampoline is
	// full (E2BIG); no start is tried before capacityUntil, and the delay
	// doubles from capacityMin to capacityMax (see startSection).
	capacity      error
	capacityUntil time.Time
	capacityDelay time.Duration
	// desired holds the policies of the last plan Replace asked for, per
	// cgroup, whether or not its bind succeeded (see currentStrict).
	desired map[uint64][]sandboxpolicy.CompiledPolicy
	// rates holds the fail-rate window of each slot in use (rates.go).
	rates map[uint32]*slotRate
	// loss holds the section's lost-verdict total over the Degraded window
	// (rates.go).
	loss lossWindow
	// helpers: the host operator consents to the runtime helper exemption
	// on pod cgroup bindings (SetRuntimeHelperExemption).
	helpers bool
	// gate: the start gate's rules are on (SetStartGate; default off).
	gate bool
	// nriEpoch and nriProven: the NRI plugin completed Synchronize on
	// connection nriEpoch, and proved the cgroups in nriProven Unselected
	// or absent (SetNRISynced; nil: not synced). With the gate on, no
	// adopted or old-set pending mark goes before it.
	nriEpoch  uint64
	nriProven map[uint64]bool
	// cgroupGone proves that a cgroup no longer exists (nil: no proof). A
	// pending mark of a gone cgroup is dropped whatever the sequence.
	cgroupGone func(cgroup uint64) bool
	// removed holds, per pod cgroup, the sequence of the write that removed
	// a sequenced record: a stale write must not mark or bind the pod
	// again. ReleasePod, a mark, and the sweep (cgroup gone) clear it.
	removed map[uint64]sandboxpolicy.Seq
	// absentKept: the start gate pods the last BindPods kept although its
	// input missed them (missing is not Unselected).
	absentKept int
	// sweeps counts the sweeps (the removed prune runs every
	// removedPruneEvery), binds the BindPods calls (the gone proof of a
	// missing pod is checked every removedPruneEvery). nriDisconnect is the
	// epoch of the last SetNRIDisconnected (a completion at or below it is
	// stale).
	sweeps, binds uint64
	nriDisconnect *uint64
}

// removedPruneEvery: the sweep checks the removed cgroups' gone proof once
// every removedPruneEvery sweeps (it is I/O under mu).
const removedPruneEvery = 32

// rememberRemoval records the sequence of a sequenced record's removal.
func (b *nodeOwner[C]) rememberRemoval(cgroup uint64, seq sandboxpolicy.Seq) {
	if b.removed == nil {
		b.removed = map[uint64]sandboxpolicy.Seq{}
	}
	if last, ok := b.removed[cgroup]; !ok || seq.Compare(last) == sandboxpolicy.SeqNewer {
		b.removed[cgroup] = seq
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
	// The plan the controller wants for this cgroup, even when its bind
	// fails below: the settle deadline keeps an adopted Strict binding by it.
	if b.desired == nil {
		b.desired = map[uint64][]sandboxpolicy.CompiledPolicy{}
	}
	b.desired[binding.CgroupID] = policies
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
		!current.pendingUnbind && !current.bindFailed && b.instance.Ready() == nil && current.check() == nil {
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
		// A slot with faults stays unconfirmed: a bind does not heal it. The
		// cause goes with it, so status can tell an unreadable witness.
		health := b.health(next)
		result := sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: health != nil}
		if h, ok := b.instance.(interface{ IoUringHeld(uint64) bool }); ok && b.instance != nil {
			result.IoUringHeld = h.IoUringHeld(binding.CgroupID)
		}
		return result, errors.Join(append(errs, health)...)
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
	if err != nil && len(b.prepared) > 0 && !b.section.inPlace {
		// The speculative prepared slots may not fit: drop only those. The
		// active pod bindings stay; if the candidate still does not fit, the
		// new binding is refused. (An in-place start leaves them out itself,
		// and its candidate already runs.)
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
	changed := len(b.combinations[combination]) != len(policies)
	for i := range policies {
		changed = changed || b.combinations[combination][i].Revision != policies[i].Revision
	}
	b.combinations[combination] = policies
	if changed {
		// The pinned manifest names the revisions (restart survival); a
		// failed write is reported by RestartStatus.
		_ = b.writeManifest()
	}
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
	delete(b.desired, binding.CgroupID)
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
	// The plan the controller wants for this cgroup, before anything below
	// can fail (a start, a full hook, no free slot): the restart deadline
	// must not read a failed prepare as "no plan" (see currentStrict).
	if b.desired == nil {
		b.desired = map[uint64][]sandboxpolicy.CompiledPolicy{}
	}
	b.desired[binding.CgroupID] = policies
	// Reserved only when the slot exists: a combination that does not fit
	// must never be carried into other workloads' replacements.
	k := key(binding)
	delete(b.reserved, k)
	reserve := func() {
		if b.reserved == nil {
			b.reserved = map[identity]reservation{}
		}
		b.reserved[k] = reservation{combination, policies, time.Now()}
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
	if err != nil && len(b.prepared) > 0 && !b.section.inPlace {
		err = b.replaceInstance(ctx, nil, extra, identity{}, nil, true)
	}
	if _, ok := b.slots[combination]; err == nil && !ok {
		// An in-place start logs a publication that failed.
		err = fmt.Errorf("%s: the combination was not published", b.section.name)
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
		// Prepare runs at most every 30 s, and only while there are slot
		// policies: the settle deadline (restart.go) acts up to 30 s late.
		return errors.Join(append(errs, b.settleByDeadline(), b.retire(ctx))...)
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
	logger.L().Info("sandbox "+b.section.name+" publish", helpers.Int("slot", int(slot)), helpers.Int("generation", int(b.generation)),
		helpers.Int("publications", int(b.stats.Publications)), helpers.Int("replacements", int(b.stats.Replacements)))
	if err := b.writeManifest(); err != nil {
		logger.L().Warning("sandbox "+b.section.name+" restart manifest not updated", helpers.Error(err))
	}
	return nil
}

// sweep frees the slots of the combinations no binding, pod, prepared or
// reserved plan uses, and deletes the buffers whose quarantine ended. A freed
// slot is reused only after its quarantine. Runs under mu.
func (b *nodeOwner[C]) sweep() error {
	// The removal order of a gone cgroup is forgotten (no pod can be marked
	// there again), whatever the section's state. The proof is I/O under
	// mu: at most once per removedPruneEvery sweeps.
	b.sweeps++
	if b.cgroupGone != nil && b.sweeps%removedPruneEvery == 0 {
		for cgroup := range b.removed {
			if b.cgroupGone(cgroup) {
				delete(b.removed, cgroup)
			}
		}
	}
	if !b.section.inPlace || b.instance == nil || b.instance.Ready() != nil {
		return nil // a frozen instance drops unused slots at its replacement
	}
	wanted := b.wanted(b.prepared, nil, b.bindings, b.pods)
	var errs []error
	freed := false
	defer func() {
		if freed {
			if err := b.writeManifest(); err != nil {
				logger.L().Warning("sandbox "+b.section.name+" restart manifest not updated", helpers.Error(err))
			}
		}
	}()
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
		freed = true
		// An unbound slot reports no more verdicts: drop the table of its
		// publication (an instance start's table holds several slots).
		if g, ok := b.content[c]; ok && g != b.generations[b.instance] {
			b.forget(g)
			b.publications[b.instance] = slices.DeleteFunc(b.publications[b.instance], func(p uint64) bool { return p == g })
		}
		delete(b.content, c)
	}
	return errors.Join(append(errs, b.sweepAdopted(), b.instance.Collect())...)
}

// sweepAdopted drops the kernel bindings of the state that no bind took
// over, once every container is bound, then frees the orphan slots.
func (b *nodeOwner[C]) sweepAdopted() error {
	var errs []error
	if b.dropPending && !b.unconfirmedBinds() {
		// A previous run's pending marks follow the mark rule here too
		// (keepPending): an in-place start on the restored state adopts
		// them while pins.adopted may be empty.
		if _, err := b.instance.DropAdopted(b.keepPending(nil)); err != nil {
			errs = append(errs, err)
		} else {
			b.dropPending = false
		}
	}
	if err := b.freeOrphans(); err != nil && !b.dropPending {
		// Before the drop a kernel binding may still hold an orphan.
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// unconfirmedBinds reports whether a container's last bind failed (or a pod's
// pending mark): its kernel binding from the state may be the one that
// protects it.
func (b *nodeOwner[C]) unconfirmedBinds() bool {
	for _, v := range b.bindings {
		if v.bindFailed {
			return true
		}
	}
	// A start gate pod whose write into this instance failed: the state's
	// entry may be its mark.
	for _, p := range b.pods {
		if p.bindPending && (p.pendingMark || p.sequenced) {
			return true
		}
	}
	return false
}

// freeOrphans frees the orphan slots; one a kernel binding still holds
// stays an orphan.
func (b *nodeOwner[C]) freeOrphans() error {
	used := map[uint32]bool{}
	for _, slot := range b.slots {
		used[slot] = true
	}
	var errs []error
	for slot := range b.orphans {
		if used[slot] {
			delete(b.orphans, slot) // published again (after a settle freed it)
			continue
		}
		if err := b.instance.Free(slot); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(b.orphans, slot)
	}
	return errors.Join(errs...)
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
		if p.pendingMark {
			// Faulted, reason "pending mark": no policy judges the pod yet.
			// Decided before any slot read: a pending pod's status never
			// comes from per-slot counters (its target slot's included).
			faulted = append(faulted, p.pod.Plan)
			continue
		}
		slot, ok := b.slots[p.combination]
		switch {
		case !ready || !ok || p.bindPending || p.pendingUnbind || b.instance.SlotHealth(slot) != nil:
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
//
// A pod of the start gate (MarkPod, or bound first by BindPodsAt) is
// sequenced. Missing from pods never removes it (missing is not Unselected);
// a plan without this section removes it, moving it to another plan or
// cgroup changes it, and both apply only at a sequence its last write admits
// (BindPodsAt; sandboxpolicy.Seq). BindPods, which has no sequence, may only
// raise it (Audit to Strict), which cannot fail open. A refused write is an
// ErrStaleSequence error for that pod with BindPodsAt (the other pods
// proceed), and is only counted with BindPods. A pending mark moves to its
// own plan's slot once it is ready, whatever the sequence, and also when the
// pod's containers started (they are armed at their own exec).
func (b *nodeOwner[C]) BindPods(ctx context.Context, pods []sandboxpolicy.PodBinding) error {
	return b.bindPods(ctx, pods, nil)
}

// BindPodsAt is BindPods with the sequence of the classification that gave
// pods (sandboxpolicy.PodGate).
func (b *nodeOwner[C]) BindPodsAt(ctx context.Context, pods []sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) error {
	return b.bindPods(ctx, pods, &seq)
}

func (b *nodeOwner[C]) bindPods(ctx context.Context, pods []sandboxpolicy.PodBinding, seq *sandboxpolicy.Seq) error {
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
	// stale refuses a write to a start gate record. Without a sequence
	// (BindPods) the refusal is expected, never an error: it must not hold
	// the section's Settle back.
	refused := 0
	stale := func(p sandboxpolicy.PodBinding) {
		if seq == nil {
			refused++
			return
		}
		errs = append(errs, b.errStale(p))
	}
	b.absentKept = 0
	// The gone proof is I/O under mu: checked for missing pods once every
	// removedPruneEvery calls.
	b.binds++
	checkGone := b.cgroupGone != nil && b.binds%removedPruneEvery == 0
	// releasedNow: released pods this call unbound; the input never binds
	// them again in the same call (only S3's sandbox tombstone, or a new
	// sandbox's MarkPod, decides about the pod afterwards).
	releasedNow := map[types.UID]bool{}
	// refusedNow: listed pods whose pending removal the input could not
	// take back; the wanted loop leaves them alone in this call.
	refusedNow := map[types.UID]bool{}
	for uid, current := range b.pods {
		// unordered: a removal no sequence decides (a released pod, or a
		// gone cgroup).
		unordered := current.released
		switch next, ok := wanted[uid]; {
		case unordered:
		case ok:
			// An empty plan (incomplete input) keeps the binding; a plan
			// with policies of this section keeps it until the pod moves
			// below (a new cgroup only once its slot is ready). A plan with
			// no policy of this section removes it. A pending removal that
			// the input cannot take back (takesBack) goes on.
			if _, policies := b.section.combination(next.Plan); len(next.Plan.Policies) == 0 || len(policies) > 0 {
				if !current.pendingUnbind || b.takesBack(current, next, seq) {
					continue
				}
				refusedNow[uid] = true
				if seq != nil {
					errs = append(errs, b.errStale(next))
				} else {
					refused++
				}
			}
		case current.sequenced && !current.pendingUnbind:
			// Missing from pods is not Unselected (an informer miss, a
			// force-deleted pod that still runs): a start gate record stays,
			// unless its cgroup is proven gone. ReleasePod and UnmarkPod
			// remove it too.
			if !checkGone || !b.cgroupGone(current.pod.CgroupID) {
				b.absentKept++
				continue
			}
			unordered = true
		}
		// An authoritative removal: a loosening of a start gate record (a
		// pending removal was admitted already).
		if !unordered && !current.pendingUnbind && !current.admits(seq, true, false) {
			stale(current.pod)
			continue
		}
		// Remove the old identity. A pending bind has none (a pending mark
		// has one). While the instance is not ready, keep the record and
		// unbind at the next ready call, as a container's pending unbind.
		switch {
		case current.bindPending && !current.pendingMark && !current.pendingUnbind:
			// Nothing bound. (A record waiting for its unbind may hold an
			// adopted entry: Unbind removes it, or does nothing.)
		case !ready:
			current.pendingUnbind = true
			current.advance(seq)
			continue
		default:
			if err := b.instance.Unbind(b.nativePod(current.pod, 0).Container); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(b.pods, uid)
		if current.released {
			releasedNow[uid] = true
		}
		if current.sequenced && !unordered {
			current.advance(seq)
			b.rememberRemoval(current.pod.CgroupID, current.lastSeq)
		}
	}
	for uid, p := range wanted {
		combination, policies := b.section.combination(p.Plan)
		strict := strictPolicies(policies)
		current := b.pods[uid]
		if releasedNow[uid] || refusedNow[uid] || (current != nil && current.released) {
			continue // only its unbind is left (above)
		}
		if current != nil && (len(policies) > 0 || len(p.Plan.Policies) == 0) {
			// Wanted again (an empty plan keeps the binding as it is). A
			// plan with no policy of this section stays a removal. Taking
			// back a start gate record's removal is a tightening.
			// The take-back and the plan change that comes with it are
			// decided together (takesBack): a refused change leaves the
			// removal pending.
			if current.pendingUnbind && !b.takesBack(current, p, seq) {
				stale(p)
				continue
			}
			current.pendingUnbind = false
		}
		if len(policies) == 0 {
			continue
		}
		if current == nil && seq != nil {
			// A pod a newer write removed is not bound again by an older
			// classification.
			if last, ok := b.removed[p.CgroupID]; ok && !seq.Admits(last, false) {
				stale(p)
				continue
			}
		}
		moved := current != nil && (p.CgroupID != current.pod.CgroupID || p.CgroupPath != current.pod.CgroupPath)
		if current != nil && current.sequenced && (moved || current.combination != combination) {
			// A plan change (or a new cgroup) of a start gate record: a
			// loosening when the class drops, a raise when it goes from
			// Audit to Strict (which needs no sequence: it cannot fail
			// open).
			was := b.class(current)
			if !current.admits(seq, was && !strict, !was && strict) {
				stale(p)
				continue
			}
			if current.pendingMark && !moved {
				if !ready {
					continue
				}
				if err := b.remark(current, p, combination, policies); err != nil {
					errs = append(errs, err)
					continue
				}
				current.advance(seq)
			}
		}
		if current != nil && !moved && !current.bindPending && !current.pendingMark && current.combination == combination {
			// The same enforcement: keep the binding, its cgroup identity
			// and its confirmation; record the newer plan (its generation)
			// and the containers' state for status and verdicts.
			current.pod.Plan = p.Plan
			current.pod.ContainersStarted = current.pod.ContainersStarted || p.ContainersStarted
			current.advance(seq)
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
		unbound := current != nil && current.bindPending
		if moved && !unbound {
			// The new cgroup's slot is ready: remove the old cgroup, then
			// bind the new one (one binding identity per pod). A failed
			// unbind keeps the record, so the next call retries.
			if err := b.instance.Unbind(b.nativePod(current.pod, 0).Container); err != nil {
				errs = append(errs, err)
				continue
			}
			unbound = true
		}
		if err := b.instance.Bind(b.nativePod(p, slot)); err != nil {
			errs = append(errs, err)
			switch {
			case unbound && current != nil && current.sequenced:
				// Nothing is bound for the pod now: a failed bind of the
				// target (not a mark), which keeps its order. Status
				// reports it faulted, never the new plan as confirmed.
				current.pod, current.combination, current.policies, current.strict = p, combination, policies, strict
				current.pendingMark, current.bindPending = false, true
			case unbound:
				// Nothing is bound for the pod now: keep a pending record,
				// so the next call retries and status reports it.
				b.pods[uid] = &podBinding{pod: p, combination: combination, bindPending: true}
			}
			continue
		}
		next := &podBinding{pod: p, combination: combination, confirmed: b.podConfirmed(p)}
		switch {
		case current != nil && current.sequenced:
			next.sequenced, next.lastSeq = true, current.lastSeq
			next.advance(seq)
		case current == nil && seq != nil:
			// A pod BindPodsAt binds first is ordered from its sequence.
			next.sequenced, next.lastSeq = true, *seq
			delete(b.removed, p.CgroupID)
		}
		if next.sequenced {
			next.strict, next.policies = strict, policies
		}
		b.pods[uid] = next
		logger.L().Info("sandbox "+b.section.name+" pod bind", helpers.String("namespace", p.Namespace), helpers.String("pod", p.PodName),
			helpers.String("cgroup", fmt.Sprint(p.CgroupID)), helpers.Int("slot", int(slot)))
	}
	if b.absentKept > 0 || refused > 0 {
		logger.L().Debug("sandbox "+b.section.name+" pod bind: start gate pods kept", helpers.Int("missingFromInput", b.absentKept),
			helpers.Int("refusedWithoutSequence", refused))
	}
	return errors.Join(append(errs, b.sweep(), b.retire(ctx))...)
}

// errEntryNotCovering: MarkPod found the pod cgroup bound, or about to be,
// in a way that does not protect it as its plan asks (nothing bound after a
// failed bind, another plan, or an adopted policy entry of a looser class).
// It never writes a mark over that, and, unlike ErrPolicyEntry, the pod is
// not covered.
var errEntryNotCovering = errors.New("the pod cgroup's entry does not protect it as its plan asks, and a pending mark never replaces it")

// entryReader reads a cgroup's kernel binding entry back (the native
// instance; enforcement.Bindings.ReadEntry and EntryOf).
type entryReader interface {
	ReadEntry(cgroup uint64) (enforcement.Entry, bool, error)
	EntryOf(enforcement.Binding) enforcement.Entry
}

// SetStartGate turns the start gate's rules on (sandboxpolicy.PodGate).
func (b *nodeOwner[C]) SetStartGate(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gate = enabled
}

// SetNRISynced records that the NRI plugin completed Synchronize on
// connection epoch, with the cgroups it proved Unselected or absent (nil:
// none proven; sandboxpolicy.PodGate). A completion older than the last
// one, or at or below the last disconnect's epoch, is stale: ignored.
func (b *nodeOwner[C]) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if epoch < b.nriEpoch || (b.nriDisconnect != nil && epoch <= *b.nriDisconnect) {
		return // an older connection's completion, or one that is gone
	}
	b.nriEpoch, b.nriProven = epoch, make(map[uint64]bool, len(proven))
	for cgroup, ok := range proven {
		if ok {
			b.nriProven[cgroup] = true
		}
	}
}

// SetNRIDisconnected records that the NRI plugin's connection epoch closed
// (sandboxpolicy.PodGate): not synced until a later connection completes.
func (b *nodeOwner[C]) SetNRIDisconnected(epoch uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nriDisconnect == nil || epoch > *b.nriDisconnect {
		d := epoch
		b.nriDisconnect = &d
	}
	b.nriProven = nil
}

// SetCgroupGone sets the proof that a cgroup no longer exists, by cgroup ID
// (nil: none; sandboxpolicy.PodGate). A pending mark of a gone cgroup is
// dropped, whatever the sequence.
func (b *nodeOwner[C]) SetCgroupGone(gone func(cgroup uint64) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cgroupGone = gone
}

// readyInstance returns why no ready instance can take a pod write.
func (b *nodeOwner[C]) readyInstance() error {
	switch {
	case b.closed:
		return fmt.Errorf("%s backend is closed", b.section.name)
	case b.instance == nil:
		return fmt.Errorf("%s: no running instance", b.section.name)
	}
	if err := b.instance.Ready(); err != nil {
		return fmt.Errorf("%s instance not ready: %w", b.section.name, err)
	}
	return nil
}

// MarkPod writes the pending mark of the pod's plan (sandboxpolicy.PodGate):
// the pod cgroup's binding to enforcement.PendingSlot with the plan's class,
// with one map write. A new mark, Audit to Strict and a plan change apply at
// a newer or equal sequence; Strict to Audit only at a newer one; otherwise
// ErrStaleSequence. A mark needs a ready instance and restart survival (it
// must outlive node-agent). It never writes over an entry on a policy slot,
// whether this run bound it or a previous run left it (adopted), and never
// removes a mark.
func (b *nodeOwner[C]) MarkPod(_ context.Context, pod sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyInstance(); err != nil {
		return err
	}
	if b.pins == nil {
		return errors.Join(fmt.Errorf("%s: restart survival is off, a pod mark would not outlive node-agent", b.section.name), b.survivalOff)
	}
	combination, policies := b.section.combination(pod.Plan)
	if len(policies) == 0 {
		return fmt.Errorf("plan has no %s section", b.section.name)
	}
	strict := strictPolicies(policies)
	current := b.pods[pod.PodUID]
	if current == nil {
		if last, ok := b.removed[pod.CgroupID]; ok && !seq.Admits(last, false) {
			return b.errStale(pod)
		}
		reader, ok := b.instance.(entryReader)
		if !ok {
			return fmt.Errorf("%s instance cannot read its kernel bindings back", b.section.name)
		}
		entry, found, err := reader.ReadEntry(pod.CgroupID)
		if err != nil {
			return err
		}
		if found && entry.Slot != enforcement.PendingSlot {
			// An entry on a policy slot that no record of this pod holds
			// (a previous run's, adopted; or another binding of this
			// cgroup): never written over. It covers the pod only when it
			// is as strict as the plan.
			if entry.Strict || !strict {
				return fmt.Errorf("%s pod %s/%s: %w", b.section.name, pod.Namespace, pod.PodName, sandboxpolicy.ErrPolicyEntry)
			}
			return fmt.Errorf("%s pod %s/%s: %w", b.section.name, pod.Namespace, pod.PodName, errEntryNotCovering)
		}
		// No entry, or a previous run's mark (adopted): this run's mark
		// takes it over with one write.
		next := &podBinding{pod: pod, combination: combination, policies: policies, pendingMark: true, strict: strict, sequenced: true, lastSeq: seq}
		if err := b.instance.Bind(b.nativeMark(next)); err != nil {
			return err
		}
		b.pods[pod.PodUID] = next
		delete(b.removed, pod.CgroupID)
		return nil
	}
	if current.pod.CgroupID != pod.CgroupID || current.pod.CgroupPath != pod.CgroupPath {
		return fmt.Errorf("%s pod %s/%s: its record holds cgroup %d (ReleasePod removes it)", b.section.name, pod.Namespace, pod.PodName, current.pod.CgroupID)
	}
	if current.pendingUnbind {
		return fmt.Errorf("%s pod %s/%s: its binding is being removed", b.section.name, pod.Namespace, pod.PodName)
	}
	if !current.pendingMark {
		// Bound (or a bind that failed): never written over. Bound to the
		// plan already, it needs no mark. A record main bound stays
		// unordered: its last write had no sequence to seed lastSeq from.
		if current.bindPending || current.combination != combination {
			// Nothing bound, or bound to another plan: not a protection
			// the caller can count on.
			return fmt.Errorf("%s pod %s/%s: %w", b.section.name, pod.Namespace, pod.PodName, errEntryNotCovering)
		}
		current.advance(&seq)
		return nil
	}
	if current.combination == combination && current.strict == strict {
		// The same mark: nothing to order. A mark whose write into a new
		// instance failed is written again (the decided state).
		if current.bindPending {
			if err := b.remark(current, pod, combination, policies); err != nil {
				return err
			}
		}
		current.advance(&seq)
		return nil
	}
	if !seq.Admits(current.lastSeq, current.strict && !strict) {
		return b.errStale(pod)
	}
	if err := b.remark(current, pod, combination, policies); err != nil {
		return err
	}
	current.advance(&seq)
	return nil
}

// remark makes a pending record the mark of pod's plan: it writes the kernel
// mark again only when the class changes or the last write failed. Runs
// under mu with a ready instance.
func (b *nodeOwner[C]) remark(p *podBinding, pod sandboxpolicy.PodBinding, combination string, policies []sandboxpolicy.CompiledPolicy) error {
	strict := strictPolicies(policies)
	if strict != p.strict || p.bindPending {
		mark := b.nativeMark(p)
		mark.Strict = strict
		if err := b.instance.Bind(mark); err != nil {
			return err
		}
		p.bindPending = false
	}
	p.pod, p.combination, p.policies, p.strict = pod, combination, policies, strict
	return nil
}

// EnsurePodBound moves a pending pod to the slot of its record's own plan
// with one map write (sandboxpolicy.PodGate), publishing the slot in place
// when it is missing. The move is sequence-neutral: that plan was admitted
// when it was recorded. Unlike BindPods, it binds a pod whose containers
// started too (each new task is armed at its own exec).
func (b *nodeOwner[C]) EnsurePodBound(ctx context.Context, uid types.UID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("%s backend is closed", b.section.name)
	}
	p := b.pods[uid]
	switch {
	case p == nil:
		return fmt.Errorf("%s: pod %s has no record", b.section.name, uid)
	case p.pendingUnbind:
		return fmt.Errorf("%s pod %s/%s: its binding is being removed", b.section.name, p.pod.Namespace, p.pod.PodName)
	case !p.pendingMark && !p.bindPending:
		return nil
	}
	if err := b.readyInstance(); err != nil {
		return err
	}
	policies := p.policies
	if len(policies) == 0 {
		policies = b.combinations[p.combination]
	}
	if len(policies) == 0 {
		return fmt.Errorf("%s pod %s/%s: the policies of its plan are not known", b.section.name, p.pod.Namespace, p.pod.PodName)
	}
	slot, ok := b.slots[p.combination]
	var err error
	switch {
	case b.section.inPlace:
		slot, err = b.publish(p.combination, policies)
		if errors.Is(err, errNoFreeSlot) {
			// A pod comes before speculation (see Replace).
			b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
			err = errors.Join(err, b.sweep())
		}
	case !ok:
		err = fmt.Errorf("%s: the pod's combination has no slot", b.section.name)
	}
	if err == nil {
		err = b.instance.Bind(b.nativePod(p.pod, slot))
	}
	if err != nil {
		return errors.Join(err, b.retire(ctx))
	}
	b.refresh(p.combination, policies)
	p.pendingMark, p.bindPending, p.confirmed = false, false, b.podConfirmed(p.pod)
	logger.L().Info("sandbox "+b.section.name+" pod bind", helpers.String("namespace", p.pod.Namespace), helpers.String("pod", p.pod.PodName),
		helpers.String("cgroup", fmt.Sprint(p.pod.CgroupID)), helpers.Int("slot", int(slot)))
	return errors.Join(b.sweep(), b.retire(ctx))
}

// ConfirmPod reports whether the pod is protected as plan asks
// (sandboxpolicy.PodGate). Confirmed only when all hold: the instance is
// ready; the pod's record has this cgroup and plan (the caller's own
// classification), is neither pending nor failed nor being removed; its slot
// is published, not PendingSlot, and healthy; and the kernel's entry for the
// cgroup reads back as that binding (bindingRingChecked aside). A pending
// record whose mark reads back is Pending; anything else is Faulted, with the
// reason.
func (b *nodeOwner[C]) ConfirmPod(uid types.UID, cgroupID uint64, plan sandboxpolicy.Plan) sandboxpolicy.PodSectionConfirmation {
	b.mu.Lock()
	defer b.mu.Unlock()
	combination, policies := b.section.combination(plan)
	c := sandboxpolicy.PodSectionConfirmation{Section: b.section.name, Strict: strictPolicies(policies)}
	faulted := func(format string, args ...any) sandboxpolicy.PodSectionConfirmation {
		c.Reason = fmt.Sprintf(format, args...)
		return c
	}
	if len(policies) == 0 {
		return faulted("the plan has no %s policy", b.section.name)
	}
	if err := b.readyInstance(); err != nil {
		return faulted("%v", err)
	}
	p := b.pods[uid]
	switch {
	case p == nil:
		return faulted("no pod binding")
	case p.pod.CgroupID != cgroupID:
		return faulted("the pod binding holds cgroup %d, not %d", p.pod.CgroupID, cgroupID)
	case p.pendingUnbind:
		return faulted("the pod binding is being removed")
	case p.bindPending:
		return faulted("the last bind of the pod failed")
	case p.combination != combination:
		return faulted("the pod binding holds another plan")
	}
	reader, ok := b.instance.(entryReader)
	if !ok {
		return faulted("the instance cannot read its kernel bindings back")
	}
	var want enforcement.Entry
	if p.pendingMark {
		want = reader.EntryOf(b.nativeMark(p))
	} else {
		slot, ok := b.slots[p.combination]
		if !ok || slot == enforcement.PendingSlot {
			return faulted("the pod's plan has no policy slot")
		}
		if err := b.instance.SlotHealth(slot); err != nil {
			return faulted("slot %d: %v", slot, err)
		}
		want = reader.EntryOf(b.nativePod(p.pod, slot))
	}
	got, found, err := reader.ReadEntry(cgroupID)
	switch {
	case err != nil:
		return faulted("read-back: %v", err)
	case !found:
		return faulted("read-back: the kernel has no entry for cgroup %d", cgroupID)
	case got != want:
		return faulted("read-back: the kernel entry is %+v, not %+v", got, want)
	}
	if p.pendingMark {
		c.State, c.Reason = sandboxpolicy.PodSectionPending, "pending mark"
		return c
	}
	c.State = sandboxpolicy.PodSectionConfirmed
	return c
}

// ReleasePod removes the pod's binding, pending or bound
// (sandboxpolicy.PodGate): the pod's last sandbox is gone. It is not ordered
// by sequence. With no record, it removes only a pending mark a previous run
// left on cgroupID (adopted), never an entry on a policy slot. While the
// instance is not ready, the record waits for the unbind (pendingUnbind) and
// the call returns an error. See PodGate.ReleasePod for the tombstone
// contract.
func (b *nodeOwner[C]) ReleasePod(ctx context.Context, uid types.UID, cgroupID uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.removed, cgroupID)
	p := b.pods[uid]
	if p == nil && cgroupID == 0 {
		return nil
	}
	if p != nil {
		delete(b.removed, p.pod.CgroupID)
	}
	if err := b.readyInstance(); err != nil {
		if p != nil {
			// Released: the next ready call unbinds it (only that), and no
			// order is kept for the pod (a new sandbox starts over).
			p.pendingUnbind, p.sequenced, p.released = true, false, true
		}
		return fmt.Errorf("%s pod release pending: %w", b.section.name, err)
	}
	if p == nil {
		return b.unbindAdoptedMark(uid, cgroupID)
	}
	if p.pendingMark || !p.bindPending || p.pendingUnbind {
		if err := b.instance.Unbind(b.nativePod(p.pod, 0).Container); err != nil {
			p.pendingUnbind = true
			return err
		}
	}
	delete(b.pods, uid)
	return errors.Join(b.sweep(), b.retire(ctx))
}

// unbindAdoptedMark removes the pending mark a previous run left on cgroupID
// (adopted), never a policy entry. Runs under mu.
func (b *nodeOwner[C]) unbindAdoptedMark(uid types.UID, cgroupID uint64) error {
	if err := b.readyInstance(); err != nil {
		return err
	}
	reader, ok := b.instance.(entryReader)
	if !ok {
		return fmt.Errorf("%s instance cannot read its kernel bindings back", b.section.name)
	}
	entry, found, err := reader.ReadEntry(cgroupID)
	if err != nil || !found || entry.Slot != enforcement.PendingSlot {
		return err // nothing of the pod's, or a policy entry: kept
	}
	// unbind removes an adopted entry whatever its identity, and an active
	// one only for its own identity (another record's stays).
	return b.instance.Unbind(enforcement.ContainerIdentity{Runtime: podRuntime, ID: string(uid), CgroupID: cgroupID})
}

// UnmarkPod removes a start gate pod (pending or bound) that an
// authoritative classification at seq found Unselected
// (sandboxpolicy.PodGate): a loosening, so only a strictly newer sequence
// removes it. A pod with no record only keeps the removal's order (a stale
// mark is refused): a previous run's mark on its cgroup is decided by
// keepPending alone (Synchronize's proof, the gone proof, or a committed
// entry), whatever the call. A released record's removal is under way: nil.
// A record main bound is not the start gate's: refused.
func (b *nodeOwner[C]) UnmarkPod(ctx context.Context, uid types.UID, cgroupID uint64, seq sandboxpolicy.Seq) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.pods[uid]
	if p == nil {
		last, known := b.removed[cgroupID]
		if known && !seq.Admits(last, true) {
			return fmt.Errorf("%s pod %s: %w", b.section.name, uid, sandboxpolicy.ErrStaleSequence)
		}
		// Only the removal's order is recorded. A previous run's mark on the
		// cgroup (adopted) is never dropped here: keepPending decides it
		// (Synchronize's proof, the gone proof, or a committed entry).
		b.rememberRemoval(cgroupID, seq)
		return nil
	}
	switch {
	case p.released:
		return nil // its removal is under way already (ReleasePod)
	case p.pod.CgroupID != cgroupID:
		return fmt.Errorf("%s pod %s/%s: its record holds cgroup %d, not %d", b.section.name, p.pod.Namespace, p.pod.PodName, p.pod.CgroupID, cgroupID)
	case !p.sequenced:
		return fmt.Errorf("%s pod %s/%s: not a start gate binding", b.section.name, p.pod.Namespace, p.pod.PodName)
	}
	// A retry of the unmark that is pending already (same sequence): not
	// stale. While the instance is not ready it returns nil; once ready it
	// unbinds.
	retry := p.pendingUnbind && seq == p.lastSeq
	if !retry && !p.admits(&seq, true, false) {
		return b.errStale(p.pod)
	}
	if err := b.readyInstance(); err != nil {
		if retry {
			return nil
		}
		p.pendingUnbind = true
		p.advance(&seq)
		b.rememberRemoval(cgroupID, p.lastSeq)
		return fmt.Errorf("%s pod unmark pending: %w", b.section.name, err)
	}
	if p.pendingMark || !p.bindPending || p.pendingUnbind {
		if err := b.instance.Unbind(b.nativePod(p.pod, 0).Container); err != nil {
			return err
		}
	}
	delete(b.pods, uid)
	p.advance(&seq)
	b.rememberRemoval(cgroupID, p.lastSeq)
	return errors.Join(b.sweep(), b.retire(ctx))
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
			if p.pendingUnbind {
				// The new instance never binds it. In place, the candidate
				// adopts its entry from the shared state: a start gate
				// record is carried, so the next ready BindPods unbinds the
				// entry (an adopted one, whatever its identity) and the
				// sweep keeps no removed mark.
				if b.section.inPlace && (p.pendingMark || p.sequenced || p.released) {
					carried := *p
					pods[uid] = &carried
				}
				continue
			}
			// A pending bind is bound by the new instance, and a pending
			// mark is carried as a mark (PendingSlot, with its class).
			carried := *p
			carried.bindPending, carried.confirmed = false, !p.pendingMark && b.podConfirmed(p.pod)
			pods[uid] = &carried
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
	if b.section.inPlace {
		return b.startInPlace(ctx, prepared, wanted, bindings, pods, withdrawn, nextKey, next)
	}
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
		initial = append(initial, b.nativeOf(p, slots))
	}
	b.generation++
	candidate, err := b.startSection(ctx, fmt.Sprintf("%s-%s-%d", b.prefix, b.section.name, b.generation), compiled, initial)
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
	logger.L().Info("sandbox "+b.section.name+" instance ready", helpers.Int("generation", int(b.generation)), helpers.Int("replacements", int(b.stats.Replacements)),
		helpers.Int("slots", len(slots)), helpers.Int("prepared", len(prepared)), helpers.Int("containers", len(bindings)), helpers.Int("pods", len(pods)))
	var errs []error
	for _, v := range withdrawn {
		errs = append(errs, v.close())
	}
	return errors.Join(errs...)
}

// startInPlace starts an instance with no slot on the section's pinned state
// (common/pin.h), then publishes every wanted combination and binds every
// container and pod with live writes. The first start resets the state
// (restart survival adopts it instead: see restart.go). A
// later start (the old instance is not ready) runs on the same state as the
// old one: the slots the owner knows and the state still holds stay.
//
// Once the candidate is ready it replaces the old instance, whatever fails
// later: both run on the same state, so after the candidate's first write a
// rollback to the old instance's view would be stale. Only a failure for
// next (under nextKey) is returned; any other publication or bind that fails
// is left for a later Replace or Prepare on the ready instance (a container
// keeps its kernel binding and stays unconfirmed meanwhile).
func (b *nodeOwner[C]) startInPlace(ctx context.Context, prepared, wanted map[string][]sandboxpolicy.CompiledPolicy, bindings map[identity]*nodeBinding, pods map[types.UID]*podBinding, withdrawn []*nodeBinding, nextKey identity, next *nodeBinding) error {
	adopting := b.adopting()
	if !b.started && b.section.resetState != nil && !adopting {
		if err := b.section.resetState(); err != nil {
			return fmt.Errorf("%s: resetting the pinned state: %w", b.section.name, err)
		}
	}
	compiled, err := b.section.compile(b.generation+1, nil)
	if err != nil {
		return err
	}
	b.generation++
	candidate, err := b.startSection(ctx, fmt.Sprintf("%s-%s-%d", b.prefix, b.section.name, b.generation), compiled, nil)
	if err != nil {
		b.restoredStartFailed(err)
		return err
	}
	b.track(candidate, b.generation)
	if err := candidate.Ready(); err != nil {
		b.restoredStartFailed(err)
		if stopErr := candidate.Stop(ctx); stopErr != nil {
			b.retiring = append(b.retiring, candidate) // retried by retire
			return errors.Join(err, stopErr)
		}
		b.untrack(candidate)
		return err
	}
	published := candidate.PublishedSlots()
	previous := b.bindings
	slots := map[string]uint32{}
	combinations := map[string][]sandboxpolicy.CompiledPolicy{}
	kept := map[uint32]bool{}
	for c, slot := range b.slots {
		if _, ok := wanted[c]; ok && published[slot] != 0 && published[slot] == b.content[c] {
			// The same state: the slot holds the owner's publication.
			slots[c], combinations[c], kept[slot] = slot, wanted[c], true
		}
	}
	// The kept slots' verdict tables move to the candidate, so retiring
	// the old instance does not forget them.
	content := map[string]uint64{}
	var tables []uint64
	for c := range slots {
		if g, ok := b.content[c]; ok {
			content[c] = g
			tables = append(tables, g)
		}
	}
	if b.publications == nil {
		b.publications = map[NodeInstance][]uint64{}
	}
	b.publications[candidate] = append(b.publications[candidate], tables...)
	if c, ok := candidate.(tableCarrier); ok && b.instance != nil {
		c.carryTables(b.instance, tables) // the gadget's rule-name tables too
	}
	if b.instance != nil {
		b.publications[b.instance] = slices.DeleteFunc(b.publications[b.instance], func(g uint64) bool { return slices.Contains(tables, g) })
		b.retiring = append(b.retiring, b.instance)
	}
	b.instance, b.slots, b.combinations, b.content, b.started = candidate, slots, combinations, content, true
	b.bindings, b.pods, b.prepared = bindings, pods, prepared
	// A restored state keeps the slots and kernel bindings the previous
	// run left until Settle: they protect its containers.
	b.orphans = map[uint32]bool{}
	for slot := range published {
		if !kept[slot] && !adopting {
			b.orphans[slot] = true
		}
	}
	// No drop before the binds below: the state's kernel bindings protect
	// the containers until this instance binds them.
	b.dropPending = false
	b.stats.Replacements++
	// Room for the publications: the orphans no kernel binding holds.
	_ = b.freeOrphans()
	// The counts of the old instance are not this one's faults. Read
	// before the binds arm again, so a fault during the re-arm counts. A
	// restored state keeps them: they belong to the previous run's
	// containers, which this run has not bound yet.
	var failed []error
	if !adopting {
		if err := candidate.ResetFaults(); err != nil {
			failed = append(failed, err)
		}
	}

	var nextErr error
	if next != nil {
		slot, err := b.publish(next.combination, wanted[next.combination])
		if errors.Is(err, errNoFreeSlot) {
			// A container comes before speculation (see Replace).
			b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
			err = errors.Join(err, b.sweep())
		}
		if err == nil {
			err = candidate.Bind(enforcement.Binding{Container: native(next.binding), Slot: slot})
		}
		if err != nil {
			nextErr = err
			delete(b.bindings, nextKey)
			if old := previous[nextKey]; old != nil {
				// Its kernel binding stays (no drop while it is unconfirmed).
				old.bindFailed = true
				b.bindings[nextKey] = old
			}
		}
	}
	// The containers' and pods' combinations come before speculation.
	needed := map[string]bool{}
	for _, v := range b.bindings {
		needed[v.combination] = true
	}
	for _, p := range b.pods {
		needed[p.combination] = true
	}
	for _, first := range []bool{true, false} {
		for c, policies := range wanted {
			if needed[c] != first {
				continue
			}
			if _, err := b.publish(c, policies); err != nil {
				delete(b.prepared, c)
				failed = append(failed, err)
			}
		}
	}
	for k, v := range b.bindings {
		if (next != nil && k == nextKey && v == next) || v.pendingUnbind {
			continue
		}
		slot, ok := b.slots[v.combination]
		if !ok {
			v.bindFailed = true
			continue
		}
		err := candidate.Bind(enforcement.Binding{Container: native(v.binding), Slot: slot})
		switch {
		case err == nil, errors.Is(err, enforcement.ErrContainerGone):
			// A gone container waits for its Withdraw.
			v.bindFailed = false
		default:
			v.bindFailed = true
			failed = append(failed, err)
		}
	}
	for _, p := range b.pods {
		if p.pendingUnbind {
			// Carried only to be unbound (replaceInstance): this instance
			// binds nothing for it. A bound record's entry is now an
			// adopted one the sweep may drop, so it is a failed bind until
			// resolved: a take-back binds it again, status reports it
			// faulted, and the sweep waits (unconfirmedBinds).
			if !p.pendingMark {
				p.bindPending = true
			}
			continue
		}
		if _, ok := b.slots[p.combination]; ok || p.pendingMark {
			// A pending mark stays a mark (PendingSlot, its class).
			err := candidate.Bind(b.nativeOf(p, b.slots))
			if err == nil || errors.Is(err, enforcement.ErrContainerGone) {
				p.bindPending = false
				continue
			}
			failed = append(failed, err)
		}
		// Not bound in the new instance: keep a pending record, so the next
		// BindPods retries and status reports it (deleting it would lose a
		// pod whose containers started).
		p.bindPending = true
	}
	for _, v := range withdrawn {
		failed = append(failed, v.close())
	}
	// The combinations no one uses wait for the caller's sweep (a
	// PrepareReplace reserves its combination after the start).
	b.dropPending = !adopting // a restored state drops at Settle
	failed = append(failed, b.sweepAdopted())
	logger.L().Info("sandbox "+b.section.name+" instance ready", helpers.Int("generation", int(b.generation)), helpers.Int("replacements", int(b.stats.Replacements)),
		helpers.Int("slots", len(b.slots)), helpers.Int("prepared", len(b.prepared)), helpers.Int("containers", len(b.bindings)), helpers.Int("pods", len(b.pods)))
	if err := errors.Join(failed...); err != nil {
		logger.L().Warning("sandbox "+b.section.name+" instance start: some publications or binds failed, retried later", helpers.Error(err))
	}
	if err := b.pinStarted(ctx); err != nil {
		// Enforcement is as it should be; only the next restart's
		// survival is missing. Status reports it (RestartStatus).
		logger.L().Warning("sandbox "+b.section.name+" instance not pinned", helpers.Error(err))
		if b.pins != nil {
			b.pins.pinErr = err
		}
	} else if b.pins != nil {
		b.pins.pinErr = nil
	}
	return nextErr
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
	for k, r := range b.reserved {
		if time.Since(r.at) > reservationTTL {
			delete(b.reserved, k)
			continue
		}
		wanted[r.combination] = r.policies
	}
	for _, v := range bindings {
		if _, ok := wanted[v.combination]; !ok {
			wanted[v.combination] = b.combinations[v.combination]
		}
	}
	for _, p := range pods {
		if p.pendingMark && p.pendingUnbind {
			continue // a removed mark: its plan's slot is not in use
		}
		if _, ok := wanted[p.combination]; !ok {
			// A pending mark's plan may have no slot yet: its own policies.
			policies := b.combinations[p.combination]
			if policies == nil {
				policies = p.policies
			}
			wanted[p.combination] = policies
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
		// Its pinned links go first: the current instance judges now.
		if err := b.unpin(i); err != nil {
			kept = append(kept, i)
			errs = append(errs, err)
			continue
		}
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
		// node-agent exits: its pinned set keeps enforcing until the next
		// start (restart survival).
		b.keepPinned(b.instance)
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

// Backoff of a start refused for attach capacity (the reference's
// nativeattach.DefaultRetry): 0.5 s, doubling to 30 s.
const (
	capacityMin = 500 * time.Millisecond
	capacityMax = 30 * time.Second
)

// startSection starts an instance. A start refused because a hook's
// trampoline is full (enforcement.AttachCapacityError: the kernel's E2BIG,
// and the failed start closed every link it attached) is a capacity
// NotReady naming the hook: no start is tried again before the backoff
// ends, and the running instance (last-good, or an adopted state) is kept.
// Runs under mu.
func (b *nodeOwner[C]) startSection(ctx context.Context, id string, compiled C, initial []enforcement.Binding) (NodeInstance, error) {
	now := time.Now()
	if b.capacity != nil && now.Before(b.capacityUntil) {
		return nil, b.capacity
	}
	instance, err := b.section.start(ctx, id, compiled, initial)
	var full *enforcement.AttachCapacityError
	if !errors.As(err, &full) {
		b.capacity, b.capacityDelay = nil, 0
		return instance, err
	}
	b.capacityDelay = min(max(2*b.capacityDelay, capacityMin), capacityMax)
	b.capacityUntil = now.Add(b.capacityDelay)
	b.capacity = errors.Join(&sandboxpolicy.EnforcementUnavailableError{Section: b.section.name, Reason: "AttachCapacity",
		Detail: fmt.Sprintf("hook %s has no free link (E2BIG); retry in %s", full.Hook, b.capacityDelay)}, err)
	logger.L().Warning("sandbox "+b.section.name+" start: attach capacity", helpers.String("hook", full.Hook),
		helpers.String("program", full.Program), helpers.String("retry", b.capacityDelay.String()))
	return nil, b.capacity
}

// removePinnedMaps is enforcement.RemovePinnedMaps. The unit tests replace it
// (main_test.go): they run sections on fake engines, and as root they would
// remove the host's real pins, under a kernel test running next to them.
var removePinnedMaps = enforcement.RemovePinnedMaps
