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
	// load. Pod bindings (bindPods) exist only for privilege: only
	// PrivilegeBackend exports BindPods.
	startEmpty bool
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

// nativePod returns the bindings controller identity of a pod cgroup. Tasks
// already in it are not armed: runc init of a container being created can be
// there.
func nativePod(p sandboxpolicy.PodBinding, slot uint32) enforcement.Binding {
	return enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: string(p.PodUID), CgroupID: p.CgroupID, CgroupPath: p.CgroupPath}, Slot: slot, SkipArming: true}
}

// emptyRetry is the shortest time between two starts of an instance with no
// slot: each start is a slow gadget load on the refresh loop.
const emptyRetry = 30 * time.Second

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
	if err != nil && (len(b.prepared) > 0 || b.podsAddSlots(extra)) {
		// The prepared set and the pod bindings may not fit; never let them
		// block a real container. bindPods binds the pods again later.
		err = b.replaceInstance(ctx, nil, extra, k, next, false)
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

// Prepare declares the combinations of the pods scheduled to this node that are
// not finished, so containers that start later find their slot. A missing
// combination replaces the node instance now, so the containers later bind
// with a live map write. Combinations no longer prepared and not in use are
// dropped at the next replacement.
func (b *nodeOwner[C]) Prepare(ctx context.Context, plans []sandboxpolicy.Plan) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("%s backend is closed", b.section.name)
	}
	prepared := map[string][]sandboxpolicy.CompiledPolicy{}
	// With startEmpty and no instance, start one even with no plans: the
	// first gadget load is slow, so the first container of a policy would
	// find no instance ready (for example the first pod after a node-agent
	// restart).
	missing := b.section.startEmpty && b.instance == nil && time.Since(b.emptyFailed) >= emptyRetry
	for _, plan := range plans {
		combination, policies := b.section.combination(plan)
		if len(policies) == 0 {
			continue
		}
		prepared[combination] = policies
		if _, ok := b.slots[combination]; !ok {
			missing = true
		}
	}
	if !missing {
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

// ClearPrepared drops the prepared set when the section has no active policy.
// It never starts an instance: the dropped combinations leave at the next
// replacement, as in Prepare.
func (b *nodeOwner[C]) ClearPrepared(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prepared = map[string][]sandboxpolicy.CompiledPolicy{}
	return b.retire(ctx)
}

// bindPods binds the given pod cgroups to the slot of their plan and unbinds
// the pod cgroups that are not given. A pod whose slot does not exist yet is
// skipped: Prepare creates the slot, and the next call binds the pod. A pod
// whose plan changes moves to the new slot in one map write; when the new slot
// does not exist yet, the pod is unbound, so a removed or edited policy never
// stays active at pod level.
func (b *nodeOwner[C]) bindPods(ctx context.Context, pods []sandboxpolicy.PodBinding) error {
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
			combination, _ := b.section.combination(next.Plan)
			if _, slot := b.slots[combination]; slot || combination == current.combination {
				continue
			}
		}
		// Not wanted, or a new cgroup for the pod: remove the old identity.
		// An instance that is not ready protects nothing.
		if ready {
			if err := b.instance.Unbind(nativePod(current.pod, 0).Container); err != nil {
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
		if err := b.instance.Bind(nativePod(p, slot)); err != nil {
			errs = append(errs, err)
			continue
		}
		b.pods[uid] = &podBinding{pod: p, combination: combination}
		logger.L().Info("sandbox "+b.section.name+" pod bind", helpers.String("namespace", p.Namespace), helpers.String("pod", p.PodName))
	}
	return errors.Join(append(errs, b.retire(ctx))...)
}

// podsAddSlots reports whether a pod binding needs a combination that no
// container binding, and not extra, needs.
func (b *nodeOwner[C]) podsAddSlots(extra map[string][]sandboxpolicy.CompiledPolicy) bool {
	used := map[string]bool{}
	for c := range extra {
		used[c] = true
	}
	for _, v := range b.bindings {
		used[v.combination] = true
	}
	for _, p := range b.pods {
		if !used[p.combination] {
			return true
		}
	}
	return false
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
	compiled, err := b.section.compile(b.generation+1, policies)
	if err != nil {
		return err
	}
	var initial []enforcement.Binding
	for _, v := range bindings {
		initial = append(initial, enforcement.Binding{Container: native(v.binding), Slot: slots[v.combination]})
	}
	for _, p := range pods {
		initial = append(initial, nativePod(p.pod, slots[p.combination]))
	}
	b.generation++
	candidate, err := b.section.start(ctx, fmt.Sprintf("%s-%s-%d", b.prefix, b.section.name, b.generation), compiled, initial)
	if err != nil {
		return err
	}
	if err = candidate.Ready(); err != nil {
		if stopErr := candidate.Stop(ctx); stopErr != nil {
			b.retiring = append(b.retiring, candidate) // retried by retire
			return errors.Join(err, stopErr)
		}
		return err
	}
	if b.instance != nil {
		b.retiring = append(b.retiring, b.instance)
	}
	b.instance, b.slots, b.combinations, b.bindings, b.prepared, b.pods = candidate, slots, wanted, bindings, prepared, pods
	b.stats.Replacements++
	return nil
}

// retire stops replaced instances and keeps the ones that still fail.
func (b *nodeOwner[C]) retire(ctx context.Context) error {
	var kept []NodeInstance
	var errs []error
	for _, i := range b.retiring {
		if err := i.Stop(ctx); err != nil {
			kept = append(kept, i)
			errs = append(errs, err)
		}
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
