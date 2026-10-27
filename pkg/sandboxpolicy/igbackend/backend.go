// Package igbackend owns strict execution-policy gadgets. The public service
// uses the persistent full backend; the explicit legacy API remains separate.
// Unsupported semantics are errors, never silently weakened rules.
package igbackend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// Engine.Start returns only after native readiness, or after failed-candidate
// cleanup. Every call owns independent maps and links.
type Engine interface {
	Start(context.Context, string, execruntime.Config, func(RawVerdict)) (Instance, error)
}
type Instance interface {
	Ready() error
	Unbind(context.Context, execruntime.ContainerIdentity) error
	Stop(context.Context) error
}

// Lease pins the exact live identity for the entire instance lifetime.
type Lease interface {
	Check() error
	Close() error
}
type Validator interface {
	Acquire(context.Context, sandboxpolicy.Binding) (Lease, error)
}

type owned struct {
	instance Instance
	lease    Lease
}
type identity struct {
	runtime, container, path string
	cgroup, mountns          uint64
	pid                      uint32
}

func key(b sandboxpolicy.Binding) identity {
	return identity{b.Runtime, b.ContainerID, b.CgroupPath, b.CgroupID, b.MountNamespace, b.PID}
}
func native(b sandboxpolicy.Binding) execruntime.ContainerIdentity {
	return execruntime.ContainerIdentity{Runtime: b.Runtime, ID: b.ContainerID, CgroupID: b.CgroupID, CgroupPath: b.CgroupPath}
}

type record struct {
	revision string
	active   *owned
	retiring []*owned
}

type Backend struct {
	mu        sync.Mutex
	engine    Engine
	validator Validator
	receiver  sandboxpolicy.VerdictReceiver
	onError   func(error)
	prefix    string
	sequence  uint64
	records   map[identity]*record
	closed    bool
}

var _ sandboxpolicy.Backend = (*Backend)(nil)

func New(engine Engine, validator Validator, receiver sandboxpolicy.VerdictReceiver, onError func(error)) (*Backend, error) {
	if engine == nil || validator == nil {
		return nil, fmt.Errorf("engine and live identity validator are required")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	return &Backend{engine: engine, validator: validator, receiver: receiver, onError: onError, prefix: hex.EncodeToString(token[:]), records: make(map[identity]*record)}, nil
}

func (b *Backend) Replace(ctx context.Context, binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) (result sandboxpolicy.ReplaceResult, resultErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	// Attest the old owner even when validation rejects the next candidate before
	// startup. Cleanup ownership is not evidence that its LSM links still protect.
	if current := b.records[k]; current != nil && current.active != nil {
		result.ProtectionUnconfirmed = errors.Join(current.active.lease.Check(), current.active.instance.Ready()) != nil
	}
	defer func() {
		if result.Committed {
			return
		}
		if current := b.records[k]; current != nil && current.active != nil {
			health := errors.Join(current.active.lease.Check(), current.active.instance.Ready())
			result.ProtectionUnconfirmed = health != nil
			if health != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("existing enforcement protection cannot be confirmed: %w", health))
			}
		}
	}()
	if b.closed {
		result.ProtectionUnconfirmed = true
		return result, fmt.Errorf("backend is closed")
	}
	// A failed candidate may temporarily need a record while cleanup is pending,
	// but a fully cleaned failed attempt must not leave a durable tombstone.
	defer func() {
		if state := b.records[k]; state != nil && state.active == nil && len(state.retiring) == 0 {
			delete(b.records, k)
		}
	}()
	r := b.records[k]
	if r != nil {
		// Finish previous cleanup before a new plan can be installed. Never restart
		// an already committed same-revision instance just to retry cleanup.
		err := cleanup(ctx, r)
		if r.active != nil && r.revision == plan.Revision {
			health := errors.Join(r.active.lease.Check(), r.active.instance.Ready())
			result = sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: r.revision, ProtectionUnconfirmed: health != nil}
			if health != nil {
				health = fmt.Errorf("existing enforcement protection cannot be confirmed: %w", health)
			}
			return result, errors.Join(err, health)
		}
		if err != nil {
			return result, err
		}
		if r.active == nil && len(r.retiring) == 0 {
			delete(b.records, k)
			r = nil
		}
	}
	ownedIdentities := 0
	for other, state := range b.records {
		if state.active == nil && len(state.retiring) == 0 {
			delete(b.records, other)
			continue
		}
		ownedIdentities++
		if other != k && other.cgroup == k.cgroup {
			var health error
			if state.active != nil {
				health = errors.Join(state.active.lease.Check(), state.active.instance.Ready())
			}
			result.ProtectionUnconfirmed = health != nil
			return result, errors.Join(fmt.Errorf("cgroup identity is still owned by another binding"), health)
		}
	}
	// Retiring-only identities still own resources. Replacement of an existing
	// identity is allowed at capacity, but admitting a new identity is not.
	if r == nil && ownedIdentities >= execpolicy.KernelMaxBindings {
		return result, fmt.Errorf("owned binding capacity exceeded (%d)", execpolicy.KernelMaxBindings)
	}
	// Check before incrementing: exhaustion remains sticky and never reuses a
	// generation, even when the last candidate failed before commit.
	if b.sequence == math.MaxUint64 {
		return result, fmt.Errorf("generation exhausted")
	}
	b.sequence++
	plan.Policies = append([]sandboxpolicy.CompiledPolicy(nil), plan.Policies...)
	for i := range plan.Policies {
		plan.Policies[i].Exec = *plan.Policies[i].Exec.DeepCopy()
	}
	config, err := Compile(binding, plan, b.sequence)
	if err != nil {
		return result, err
	}
	lease, err := b.validator.Acquire(ctx, binding)
	if err != nil {
		return result, err
	}
	id := fmt.Sprintf("sandbox-exec-%s-%d", b.prefix, b.sequence)
	candidate, err := b.engine.Start(ctx, id, config, func(raw RawVerdict) {
		verdict, err := DecodeVerdict(binding, plan, config.Entries[0].Generation, raw)
		if err == nil && b.receiver != nil {
			err = b.receiver.ReportVerdict(context.Background(), verdict)
		}
		if err != nil && b.onError != nil {
			b.onError(err)
		}
	})
	if err != nil {
		return result, errors.Join(err, lease.Close())
	}
	next := &owned{instance: candidate, lease: lease}
	if err := errors.Join(lease.Check(), candidate.Ready()); err != nil {
		if r == nil {
			r = &record{}
			b.records[k] = r
		}
		r.retiring = append(r.retiring, next)
		return result, errors.Join(err, cleanup(ctx, r))
	}
	if r == nil {
		r = &record{}
		b.records[k] = r
	}
	if r.active != nil {
		r.retiring = append(r.retiring, r.active)
	}
	r.active, r.revision = next, plan.Revision // The new independent instance is now authoritative.
	result = sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: plan.Revision}
	return result, cleanup(ctx, r)
}

func (b *Backend) Withdraw(ctx context.Context, binding sandboxpolicy.Binding) (result sandboxpolicy.WithdrawResult, resultErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key(binding)
	r := b.records[k]
	if r == nil {
		return sandboxpolicy.WithdrawResult{Committed: true}, nil
	}
	// An incomplete withdrawal retains ownership, not necessarily protection.
	// Re-attest after either cleanup or unbind fails, as either operation may
	// race native failure. A retiring-only record has no confirmed active owner.
	defer func() {
		if result.Committed {
			return
		}
		health := fmt.Errorf("no active enforcement owner")
		if r.active != nil {
			health = errors.Join(r.active.lease.Check(), r.active.instance.Ready())
		}
		result.ProtectionUnconfirmed = health != nil
		if health != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("existing enforcement protection cannot be confirmed: %w", health))
		}
	}()
	// Retired instances may still enforce during failed cleanup. Do not report
	// withdrawal committed while any of those old links may protect the binding.
	if err := cleanup(ctx, r); err != nil {
		return sandboxpolicy.WithdrawResult{}, err
	}
	if r.active != nil {
		if err := r.active.instance.Unbind(ctx, native(binding)); err != nil {
			return sandboxpolicy.WithdrawResult{}, err
		}
		r.retiring = append(r.retiring, r.active)
		r.active = nil
	}
	result = sandboxpolicy.WithdrawResult{Committed: true}
	if err := cleanup(ctx, r); err != nil {
		return result, err
	}
	delete(b.records, k)
	return result, nil
}

func cleanup(ctx context.Context, r *record) error {
	var pending []*owned
	var errs []error
	for _, old := range r.retiring {
		if err := old.instance.Stop(ctx); err != nil {
			pending = append(pending, old)
			errs = append(errs, err)
			continue
		}
		// References outlive links, including when stopping was canceled earlier.
		if err := old.lease.Close(); err != nil {
			pending = append(pending, old)
			errs = append(errs, err)
		}
	}
	r.retiring = pending
	return errors.Join(errs...)
}

// Compile is an explicit interim legacy converter, not the full exec backend.
func Compile(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan, generation uint64) (execruntime.Config, error) {
	var config execruntime.Config
	if plan.Revision == "" || len(plan.Policies) != 1 {
		return config, fmt.Errorf("legacy exec backend requires exactly one policy and a revision")
	}
	p := plan.Policies[0]
	if p.Mode != "audit" && p.Mode != "enforce" {
		return config, fmt.Errorf("legacy backend requires an active policy")
	}
	if p.RootRole != "" && p.RootRole != "agent" {
		return config, fmt.Errorf("legacy exec backend cannot represent root roles")
	}
	doc := execpolicy.Document{Version: 1, Binding: execpolicy.Binding{Container: &execpolicy.Container{Runtime: binding.Runtime, ID: binding.ContainerID}}, Policy: execpolicy.Policy{Mode: string(p.Mode), Exec: execpolicy.Section{Default: string(p.Exec.Default)}}}
	for _, r := range p.Exec.Rules {
		if r.Actor != nil || len(r.Target.PathClass) > 0 || r.Target.FromImage != nil || len(r.Target.FSType) > 0 || r.Target.Argv != nil || r.Target.SetRole != "" {
			return config, fmt.Errorf("rule %q contains predicates unsupported by legacy exec backend", r.Name)
		}
		doc.Policy.Exec.Rules = append(doc.Policy.Exec.Rules, execpolicy.Rule{Name: r.Name, Target: execpolicy.Target{Path: append([]string(nil), r.Target.Path...)}, Action: string(r.Action), Mode: string(r.Mode), Origin: r.Origin})
	}
	entries, err := execpolicy.CompileKernel(doc, generation)
	if err != nil {
		return config, err
	}
	config.Entries = entries
	// No discovery Targets: the exact prevalidated identity is the only member.
	config.InitialBindings = []execruntime.ContainerIdentity{native(binding)}
	return config, nil
}

// Close removes this backend's exact bindings and finishes their cleanup. Call
// again after an error; it does not stop unrelated instances on the runtime.
func (b *Backend) Close(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	keys := make([]identity, 0, len(b.records))
	for k := range b.records {
		keys = append(keys, k)
	}
	b.mu.Unlock()
	var errs []error
	for _, k := range keys {
		_, err := b.Withdraw(ctx, sandboxpolicy.Binding{Runtime: k.runtime, ContainerID: k.container, CgroupPath: k.path, CgroupID: k.cgroup, MountNamespace: k.mountns, PID: k.pid})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
