package igbackend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
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
	prepared     map[string][]sandboxpolicy.CompiledPolicy
	retiring     []NodeInstance
	stats        NodeStats
	closed       bool
}

func newNodeOwner[C any](section nodeSection[C], validator Validator, prefix string) nodeOwner[C] {
	return nodeOwner[C]{section: section, validator: validator, prefix: prefix, slots: map[string]uint32{}, combinations: map[string][]sandboxpolicy.CompiledPolicy{}, bindings: map[identity]*nodeBinding{}, prepared: map[string][]sandboxpolicy.CompiledPolicy{}}
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
	err := b.replaceInstance(ctx, b.prepared, extra, k, next)
	if err != nil && len(b.prepared) > 0 {
		// The prepared set may not fit; never let it block a real container.
		err = b.replaceInstance(ctx, nil, extra, k, next)
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
	missing := false
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
	return errors.Join(b.replaceInstance(ctx, prepared, nil, identity{}, nil), b.retire(ctx))
}

// replaceInstance starts a candidate with every combination in use or prepared
// (plus extra), binds every container (plus next, under nextKey), and only then
// stops the old instance. On failure the old instance and state stay.
func (b *nodeOwner[C]) replaceInstance(ctx context.Context, prepared, extra map[string][]sandboxpolicy.CompiledPolicy, nextKey identity, next *nodeBinding) error {
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
	b.instance, b.slots, b.combinations, b.bindings, b.prepared = candidate, slots, wanted, bindings, prepared
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
	return errors.Join(append(errs, b.retire(ctx))...)
}
