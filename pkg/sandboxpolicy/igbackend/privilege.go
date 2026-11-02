package igbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// PrivilegeEngine starts one node-wide enforce_privilege instance. Start returns
// only after native readiness, or after failed-candidate cleanup.
type PrivilegeEngine interface {
	Start(ctx context.Context, id string, config privruntime.Config) (PrivilegeInstance, error)
}

type PrivilegeInstance interface {
	Ready() error
	Bind(enforcement.Binding) error
	Unbind(enforcement.ContainerIdentity) error
	Stop(context.Context) error
}

// PrivilegeStats counts how container binds found their policy slot.
type PrivilegeStats struct {
	// Prepared: the slot already existed (created when the pod was scheduled,
	// or used by another container), so the bind was a live map write.
	Prepared uint64
	// Replaced: the slot was missing, so the node instance was replaced.
	Replaced uint64
	// Replacements counts every node instance replacement.
	Replacements uint64
}

type privilegeBinding struct {
	binding     sandboxpolicy.Binding
	revision    string
	combination string
	// lease pins the live container identity while it is bound (nil when the
	// backend has no validator).
	lease Lease
}

func (p *privilegeBinding) check() error {
	if p.lease == nil {
		return nil
	}
	return p.lease.Check()
}

func (p *privilegeBinding) close() error {
	if p.lease == nil {
		return nil
	}
	return p.lease.Close()
}

// PrivilegeBackend owns ONE enforce_privilege instance per node.
//
// A slot is one combination of privilege policies; containers with the same
// combination share it. Binding or unbinding a container is a live map write.
// A combination that the running instance does not have (a new or changed
// policy) replaces the node instance: start the candidate with every slot in
// use, wait until it is ready with every container bound, then stop the old
// instance. Both enforce during the overlap. Unused slots are dropped at the
// next replacement.
type PrivilegeBackend struct {
	mu           sync.Mutex
	engine       PrivilegeEngine
	validator    Validator
	prefix       string
	generation   uint64
	instance     PrivilegeInstance
	slots        map[string]uint32 // combination -> slot in instance
	combinations map[string][]sandboxpolicy.CompiledPolicy
	bindings     map[identity]*privilegeBinding
	prepared     map[string][]sandboxpolicy.CompiledPolicy
	retiring     []PrivilegeInstance
	stats        PrivilegeStats
	closed       bool
}

var (
	_ sandboxpolicy.Backend            = (*PrivilegeBackend)(nil)
	_ sandboxpolicy.ProtectionAttester = (*PrivilegeBackend)(nil)
)

// NewPrivilege creates the node backend. validator verifies the live container
// identity before a bind and holds it while bound; nil skips the check (tests).
func NewPrivilege(engine PrivilegeEngine, validator Validator, prefix string) (*PrivilegeBackend, error) {
	if engine == nil {
		return nil, fmt.Errorf("privilege engine is required")
	}
	return &PrivilegeBackend{engine: engine, validator: validator, prefix: prefix, slots: map[string]uint32{}, combinations: map[string][]sandboxpolicy.CompiledPolicy{}, bindings: map[identity]*privilegeBinding{}, prepared: map[string][]sandboxpolicy.CompiledPolicy{}}, nil
}

// Combination returns the privilege policies of a plan, sorted, and their key.
func Combination(plan sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy) {
	var policies []sandboxpolicy.CompiledPolicy
	for _, p := range plan.Policies {
		if p.Privilege != nil {
			policies = append(policies, p)
		}
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Identity.UID < policies[j].Identity.UID })
	type part struct {
		UID, Name, Mode string
		Privilege       any
	}
	parts := make([]part, len(policies))
	for i, p := range policies {
		parts[i] = part{string(p.Identity.UID), p.Identity.Namespace + "/" + p.Identity.Name, string(p.Mode), p.Privilege}
	}
	data, _ := json.Marshal(parts) // concrete JSON-serializable API structs
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), policies
}

func (b *PrivilegeBackend) Stats() PrivilegeStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *PrivilegeBackend) Replace(ctx context.Context, binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) (sandboxpolicy.ReplaceResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	current := b.bindings[k]
	var result sandboxpolicy.ReplaceResult
	var health error
	if current != nil {
		result.ActiveRevision = current.revision
		health = errors.Join(b.instance.Ready(), current.check())
		result.ProtectionUnconfirmed = health != nil
	}
	if b.closed {
		return result, fmt.Errorf("privilege backend is closed")
	}
	combination, policies := Combination(plan)
	if len(policies) == 0 {
		return result, fmt.Errorf("plan has no privilege section")
	}
	if b.instance != nil && health == nil {
		health = b.instance.Ready()
	}
	if current != nil && current.revision == plan.Revision && current.combination == combination && health == nil {
		result.Committed = true
		return result, b.retire(ctx)
	}
	next := &privilegeBinding{binding: binding, revision: plan.Revision, combination: combination}
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
	}
	return commit()
}

func (b *PrivilegeBackend) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
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

func (b *PrivilegeBackend) Attest(_ context.Context, binding sandboxpolicy.Binding, revision string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	current := b.bindings[key(binding)]
	if current == nil || current.revision != revision || b.instance == nil {
		return fmt.Errorf("privilege revision %q is not active", revision)
	}
	return errors.Join(b.instance.Ready(), current.check())
}

// Prepare declares the combinations of the pods scheduled to this node that are
// not finished, so containers that start later find their slot. A missing combination replaces the node
// instance now, so the containers later bind with a live map write.
// Combinations no longer prepared and not in use are dropped at the next
// replacement.
func (b *PrivilegeBackend) Prepare(ctx context.Context, plans []sandboxpolicy.Plan) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fmt.Errorf("privilege backend is closed")
	}
	prepared := map[string][]sandboxpolicy.CompiledPolicy{}
	missing := false
	for _, plan := range plans {
		combination, policies := Combination(plan)
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
func (b *PrivilegeBackend) replaceInstance(ctx context.Context, prepared, extra map[string][]sandboxpolicy.CompiledPolicy, nextKey identity, next *privilegeBinding) error {
	bindings := map[identity]*privilegeBinding{}
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
	docs := make([][]privpolicy.Document, len(keys))
	for i, c := range keys {
		slots[c] = uint32(i)
		for _, p := range wanted[c] {
			doc, err := privpolicy.FromAPI(p.Identity.Namespace+"/"+p.Identity.Name, p.Mode, *p.Privilege)
			if err != nil {
				return err
			}
			docs[i] = append(docs[i], doc)
		}
	}
	compiled, err := privpolicy.CompileSlots(docs, b.generation+1)
	if err != nil {
		return err
	}
	config := privruntime.Config{Policy: compiled}
	for _, v := range bindings {
		config.InitialBindings = append(config.InitialBindings, enforcement.Binding{Container: native(v.binding), Slot: slots[v.combination]})
	}
	b.generation++
	candidate, err := b.engine.Start(ctx, fmt.Sprintf("%s-privilege-%d", b.prefix, b.generation), config)
	if err != nil {
		return err
	}
	if err = candidate.Ready(); err != nil {
		return errors.Join(err, candidate.Stop(ctx))
	}
	if b.instance != nil {
		b.retiring = append(b.retiring, b.instance)
	}
	b.instance, b.slots, b.combinations, b.bindings, b.prepared = candidate, slots, wanted, bindings, prepared
	b.stats.Replacements++
	return nil
}

// retire stops replaced instances and keeps the ones that still fail.
func (b *PrivilegeBackend) retire(ctx context.Context) error {
	var kept []PrivilegeInstance
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

func (b *PrivilegeBackend) Close(ctx context.Context) error {
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
	b.bindings = map[identity]*privilegeBinding{}
	return errors.Join(append(errs, b.retire(ctx))...)
}
