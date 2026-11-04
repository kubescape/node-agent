package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// Section names of the node-wide section backends.
const (
	SectionPrivilege = "privilege"
	SectionNetwork   = "network"
)

// SectionBackend drives one backend per policy section.
//
// A binding whose old and new plans have only exec sections goes straight to
// the exec backend, unchanged. Otherwise the plan is split into an exec plan
// and one plan per other section (privilege, network), each with its own
// revision. When no policy object holds exec and another section, the exec
// plan and its revision are what the controller gives the exec policies alone,
// so adding, editing or removing a privilege or network policy does not restart
// exec. When one object holds both, its generation is part of the exec revision
// (as in the exec-only path): an edit of only its other section restarts exec
// once. This is a known limit; the generation must stay in the plan for status
// staleness.
//
// Commit follows the Backend contract of each section: a section that returns
// Committed=true is committed, even with a cleanup error. If a later section
// does not commit, the earlier sections return to their previous plans.
type SectionBackend struct {
	mu       sync.Mutex
	exec     Backend
	sections []*section
	active   map[string]sectionPlans
	// prepareMu guards section.prepared.
	prepareMu sync.Mutex
}

// section is one section backend next to exec.
type section struct {
	name    string
	backend Backend // nil: the section is rejected with unavailable
	// unavailable says why the section is rejected (backend == nil).
	unavailable error
	// part returns the section of a policy, nil when the policy has none.
	part func(CompiledPolicy) any
	// strip removes the section from a policy for the exec plan.
	strip func(*CompiledPolicy)
	// prepared: the last PrepareSections call prepared this section.
	prepared bool
}

type sectionPlans struct {
	revision string
	exec     Plan
	// other and cleanup have one entry per SectionBackend.sections. cleanup:
	// a withdraw committed with a cleanup error; later calls retry it.
	other   []Plan
	cleanup []bool
}

var (
	_ Backend            = (*SectionBackend)(nil)
	_ ProtectionAttester = (*SectionBackend)(nil)
)

// NewSectionBackend combines the section backends. When privilege is nil,
// unavailable says why (nil means no privilege image is configured). The
// network section is unavailable until WithNetwork sets it.
func NewSectionBackend(exec, privilege Backend, unavailable error) (*SectionBackend, error) {
	if exec == nil {
		return nil, fmt.Errorf("exec backend is required")
	}
	s := &SectionBackend{exec: exec, active: map[string]sectionPlans{}, sections: []*section{
		{name: SectionPrivilege, part: func(p CompiledPolicy) any {
			if p.Privilege == nil {
				return nil
			}
			return p.Privilege
		}, strip: func(p *CompiledPolicy) { p.Privilege = nil }},
		{name: SectionNetwork, part: func(p CompiledPolicy) any {
			if p.Network == nil {
				return nil
			}
			return p.Network
		}, strip: func(p *CompiledPolicy) { p.Network = nil }},
	}}
	s.set(SectionPrivilege, privilege, unavailable, "PrivilegeNotConfigured", "no privilege gadget image is configured")
	s.set(SectionNetwork, nil, nil, "NetworkNotConfigured", "no network gadget image is configured")
	return s, nil
}

// WithNetwork sets the network section backend. When network is nil,
// unavailable says why (nil means no network image is configured).
func (s *SectionBackend) WithNetwork(network Backend, unavailable error) *SectionBackend {
	s.set(SectionNetwork, network, unavailable, "NetworkNotConfigured", "no network gadget image is configured")
	return s
}

func (s *SectionBackend) set(name string, backend Backend, unavailable error, reason, detail string) {
	for _, sec := range s.sections {
		if sec.name != name {
			continue
		}
		if backend == nil && unavailable == nil {
			unavailable = &EnforcementUnavailableError{Section: name, Reason: reason, Detail: detail}
		}
		if backend != nil {
			unavailable = nil
		}
		sec.backend, sec.unavailable = backend, unavailable
	}
}

// SectionUnavailable returns why a section cannot be enforced, or nil.
func (s *SectionBackend) SectionUnavailable(name string) error {
	for _, sec := range s.sections {
		if sec.name == name {
			return sec.unavailable
		}
	}
	return nil
}

// execOnly reports whether the plans need only the exec backend.
func (p sectionPlans) execOnly() bool {
	for i := range p.other {
		if p.other[i].Revision != "" || p.cleanup[i] {
			return false
		}
	}
	return true
}

// normalize gives plans without section entries (no state yet) their length.
func (s *SectionBackend) normalize(p sectionPlans) sectionPlans {
	if len(p.other) == 0 {
		p.other, p.cleanup = make([]Plan, len(s.sections)), make([]bool, len(s.sections))
	}
	return p
}

// Prepare passes the plans of pods scheduled to this node, whose containers have
// not finished (running ones included), to each section backend that can create
// their slots before new containers start.
func (s *SectionBackend) Prepare(ctx context.Context, plans []Plan) error {
	return s.PrepareSections(ctx, plans, nil)
}

// PrepareSections prepares like Prepare, but only the sections in active
// (nil: every section). A section with no active policy is not prepared, so
// a backend that loads its gadget before the first plan (privilege) does not
// load it for a policy of another section.
func (s *SectionBackend) PrepareSections(ctx context.Context, plans []Plan, active map[string]bool) error {
	s.prepareMu.Lock()
	defer s.prepareMu.Unlock()
	var errs []error
	for _, sec := range s.sections {
		preparer, ok := sec.backend.(SlotPreparer)
		if !ok {
			continue
		}
		if active != nil && !active[sec.name] {
			if sec.prepared {
				// The section has just become inactive: clear its
				// prepared set once, so its slots are not kept.
				errs = append(errs, preparer.Prepare(ctx, nil))
			}
			sec.prepared = false
			continue
		}
		sec.prepared = true
		errs = append(errs, preparer.Prepare(ctx, plans))
	}
	return errors.Join(errs...)
}

// BindPods passes the pod bindings to a privilege backend that can bind pod
// cgroups. Pod bindings exist only for the privilege section.
func (s *SectionBackend) BindPods(ctx context.Context, pods []PodBinding) error {
	for _, sec := range s.sections {
		if sec.name != SectionPrivilege {
			continue
		}
		if binder, ok := sec.backend.(PodBinder); ok {
			return binder.BindPods(ctx, pods)
		}
	}
	return nil
}

// Exec returns the exec section backend.
func (s *SectionBackend) Exec() Backend { return s.exec }

func (s *SectionBackend) split(plan Plan) sectionPlans {
	out := s.normalize(sectionPlans{revision: plan.Revision})
	// A section compiler reads each policy's identity, mode and section.
	type sectionPart struct {
		Identity PolicyIdentity
		Mode     api.PolicyMode
		Section  any
	}
	found := false
	for i, sec := range s.sections {
		var parts []sectionPart
		for _, p := range plan.Policies {
			if part := sec.part(p); part != nil {
				out.other[i].Policies = append(out.other[i].Policies, p)
				id := p.Identity
				id.Generation = 0 // an edit of another section must not change this revision
				parts = append(parts, sectionPart{id, p.Mode, part})
			}
		}
		if len(parts) == 0 {
			continue
		}
		found = true
		sort.Slice(parts, func(a, b int) bool { return parts[a].Identity.UID < parts[b].Identity.UID })
		out.other[i].Revision = digest(parts)
	}
	if !found {
		out.exec = plan
		return out
	}
	shared := false
	for _, p := range plan.Policies {
		if p.Exec.Default != "" && s.hasOtherSection(p) {
			shared = true
		}
	}
	if !shared {
		// No policy object carries exec and another section: the exec plan is
		// the plan of the policies without another section, with the revision
		// the controller gives that plan alone. Adding or removing a privilege
		// or network policy then keeps the exec revision, so exec does not
		// restart.
		for _, p := range plan.Policies {
			if !s.hasOtherSection(p) {
				out.exec.Policies = append(out.exec.Policies, p)
			}
		}
		if len(out.exec.Policies) > 0 {
			out.exec.Revision = digest(out.exec.Policies)
		}
		return out
	}
	type execPart struct {
		Identity PolicyIdentity
		Mode     api.PolicyMode
		RootRole string
		Exec     api.ExecSection
	}
	var execParts []execPart
	for _, p := range plan.Policies {
		if p.Exec.Default == "" {
			continue
		}
		e := p
		for _, sec := range s.sections {
			sec.strip(&e)
		}
		out.exec.Policies = append(out.exec.Policies, e)
		execParts = append(execParts, execPart{p.Identity, p.Mode, p.RootRole, p.Exec})
	}
	if len(execParts) > 0 {
		out.exec.Revision = digest(execParts)
	}
	return out
}

// hasOtherSection reports whether a policy has a section other than exec.
func (s *SectionBackend) hasOtherSection(p CompiledPolicy) bool {
	for _, sec := range s.sections {
		if sec.part(p) != nil {
			return true
		}
	}
	return false
}

type sectionResult struct {
	committed, unconfirmed bool
	err                    error
}

// apply moves one section from old to want.
func apply(ctx context.Context, backend Backend, binding Binding, old, want Plan) sectionResult {
	switch {
	case want.Revision == old.Revision:
		if want.Revision == "" {
			return sectionResult{committed: true}
		}
		fallthrough // same plan: retry cleanup and confirm protection
	case want.Revision != "":
		r, err := backend.Replace(ctx, binding, want)
		committed := r.Committed && r.ActiveRevision == want.Revision
		if !committed && err == nil {
			err = fmt.Errorf("replace not committed")
		}
		return sectionResult{committed, r.ProtectionUnconfirmed, err}
	default:
		r, err := backend.Withdraw(ctx, binding)
		if !r.Committed && err == nil {
			err = fmt.Errorf("withdraw not committed")
		}
		return sectionResult{r.Committed, r.ProtectionUnconfirmed, err}
	}
}

func (s *SectionBackend) Replace(ctx context.Context, binding Binding, plan Plan) (ReplaceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindingKey(binding)
	old := s.normalize(s.active[k])
	want := s.split(plan)
	if old.execOnly() && want.execOnly() {
		r, err := s.exec.Replace(ctx, binding, plan)
		if r.Committed {
			s.active[k] = want
		}
		return r, err
	}
	for i, sec := range s.sections {
		if sec.backend == nil && want.other[i].Revision != "" {
			return ReplaceResult{}, sec.unavailable
		}
	}

	e := apply(ctx, s.exec, binding, old.exec, want.exec)
	if !e.committed {
		return ReplaceResult{ProtectionUnconfirmed: e.unconfirmed}, fmt.Errorf("exec section: %w", e.err)
	}
	unconfirmed := e.unconfirmed
	errs := []error{e.err}
	for i, sec := range s.sections {
		if sec.backend == nil {
			continue
		}
		oldPlan := old.other[i]
		if old.cleanup[i] && oldPlan.Revision == "" {
			oldPlan.Revision = "cleanup" // forces a Withdraw retry
		}
		r := apply(ctx, sec.backend, binding, oldPlan, want.other[i])
		unconfirmed = unconfirmed || r.unconfirmed
		if !r.committed {
			// Return the earlier sections and exec to their previous plans.
			failure := []error{fmt.Errorf("%s section: %w", sec.name, r.err)}
			for j := i - 1; j >= 0; j-- {
				if s.sections[j].backend == nil {
					continue
				}
				back := apply(ctx, s.sections[j].backend, binding, want.other[j], old.other[j])
				unconfirmed = unconfirmed || back.unconfirmed || !back.committed
				failure = append(failure, back.err)
			}
			back := apply(ctx, s.exec, binding, want.exec, old.exec)
			return ReplaceResult{ProtectionUnconfirmed: unconfirmed || back.unconfirmed || !back.committed},
				errors.Join(append(failure, back.err)...)
		}
		want.cleanup[i] = want.other[i].Revision == "" && r.err != nil
		errs = append(errs, r.err)
	}
	s.active[k] = want
	return ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: unconfirmed}, errors.Join(errs...)
}

func (s *SectionBackend) Withdraw(ctx context.Context, binding Binding) (WithdrawResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindingKey(binding)
	old := s.normalize(s.active[k])
	if old.execOnly() {
		r, err := s.exec.Withdraw(ctx, binding)
		if r.Committed {
			delete(s.active, k)
		}
		return r, err
	}
	e, eerr := s.exec.Withdraw(ctx, binding)
	result := WithdrawResult{Committed: e.Committed, ProtectionUnconfirmed: e.ProtectionUnconfirmed}
	errs := []error{eerr}
	left := s.normalize(sectionPlans{})
	if !e.Committed {
		left.exec = old.exec
	}
	someCommitted, cleanup := e.Committed, false
	for i, sec := range s.sections {
		if sec.backend == nil || (old.other[i].Revision == "" && !old.cleanup[i]) {
			continue
		}
		r, err := sec.backend.Withdraw(ctx, binding)
		errs = append(errs, err)
		result.Committed = result.Committed && r.Committed
		result.ProtectionUnconfirmed = result.ProtectionUnconfirmed || r.ProtectionUnconfirmed
		someCommitted = someCommitted || r.Committed
		switch {
		case r.Committed && err != nil:
			left.cleanup[i], cleanup = true, true
		case !r.Committed:
			left.other[i], left.cleanup[i] = old.other[i], old.cleanup[i]
		}
	}
	// One section removed and another not: the old protection is gone.
	result.ProtectionUnconfirmed = result.ProtectionUnconfirmed || (someCommitted && !result.Committed)
	switch {
	case result.Committed && !cleanup:
		delete(s.active, k)
	case someCommitted:
		s.active[k] = left
	}
	return result, errors.Join(errs...)
}

// Attest checks each section that is active for the binding.
func (s *SectionBackend) Attest(ctx context.Context, binding Binding, revision string) error {
	s.mu.Lock()
	plans, ok := s.active[bindingKey(binding)]
	s.mu.Unlock()
	plans = s.normalize(plans)
	if !ok || plans.execOnly() {
		if a, isAttester := s.exec.(ProtectionAttester); isAttester {
			return a.Attest(ctx, binding, revision)
		}
		return fmt.Errorf("exec backend cannot attest")
	}
	if plans.revision != revision {
		return fmt.Errorf("revision %q is not active", revision)
	}
	var errs []error
	check := func(backend Backend, plan Plan) {
		if plan.Revision == "" {
			return
		}
		a, isAttester := backend.(ProtectionAttester)
		if !isAttester {
			errs = append(errs, fmt.Errorf("backend cannot attest"))
			return
		}
		errs = append(errs, a.Attest(ctx, binding, plan.Revision))
	}
	check(s.exec, plans.exec)
	for i, sec := range s.sections {
		check(sec.backend, plans.other[i])
	}
	return errors.Join(errs...)
}

func (s *SectionBackend) Close(ctx context.Context) error {
	var errs []error
	backends := []Backend{s.exec}
	for _, sec := range s.sections {
		backends = append(backends, sec.backend)
	}
	for _, backend := range backends {
		if c, ok := backend.(interface{ Close(context.Context) error }); ok {
			errs = append(errs, c.Close(ctx))
		}
	}
	return errors.Join(errs...)
}
