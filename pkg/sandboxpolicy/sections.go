package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// SectionBackend drives one backend per policy section.
//
// A binding whose old and new plans have no privilege section goes straight to
// the exec backend, unchanged. Otherwise the plan is split into an exec plan
// and a privilege plan, each with its own revision. A policy's generation is part
// of the exec revision, so an edit restarts exec only when exec and privilege
// share one policy object; sections in separate policies stay independent.
//
// Commit follows the Backend contract of each section: a section that returns
// Committed=true is committed, even with a cleanup error. If the second section
// does not commit, the first section returns to its previous plan.
type SectionBackend struct {
	mu        sync.Mutex
	exec      Backend
	privilege Backend // nil: privilege sections are rejected
	active    map[string]sectionPlans
}

type sectionPlans struct {
	revision        string
	exec, privilege Plan
	// privilegeCleanup: a privilege withdraw committed with a cleanup error;
	// later calls retry it.
	privilegeCleanup bool
}

var (
	_ Backend            = (*SectionBackend)(nil)
	_ ProtectionAttester = (*SectionBackend)(nil)
)

func NewSectionBackend(exec, privilege Backend) (*SectionBackend, error) {
	if exec == nil {
		return nil, fmt.Errorf("exec backend is required")
	}
	return &SectionBackend{exec: exec, privilege: privilege, active: map[string]sectionPlans{}}, nil
}

// execOnly reports whether the plans need only the exec backend.
func (p sectionPlans) execOnly() bool { return p.privilege.Revision == "" && !p.privilegeCleanup }

// Prepare passes the plans of pods scheduled to this node, whose containers have
// not finished (running ones included), to a privilege backend that can create
// their slots before new containers start.
func (s *SectionBackend) Prepare(ctx context.Context, plans []Plan) error {
	preparer, ok := s.privilege.(SlotPreparer)
	if !ok {
		return nil
	}
	return preparer.Prepare(ctx, plans)
}

// Exec returns the exec section backend.
func (s *SectionBackend) Exec() Backend { return s.exec }

func split(plan Plan) (sectionPlans, error) {
	s := sectionPlans{revision: plan.Revision}
	type execPart struct {
		Identity PolicyIdentity
		Mode     api.PolicyMode
		RootRole string
		Exec     api.ExecSection
	}
	var execParts []execPart
	for _, p := range plan.Policies {
		if p.Privilege != nil {
			s.privilege.Policies = append(s.privilege.Policies, p)
		}
	}
	if len(s.privilege.Policies) == 0 {
		s.exec = plan
		return s, nil
	}
	// The privilege compiler reads each policy's identity, mode and section.
	type privilegePart struct {
		Identity  PolicyIdentity
		Mode      api.PolicyMode
		Privilege *api.PrivilegeSection
	}
	parts := make([]privilegePart, 0, len(s.privilege.Policies))
	for _, p := range s.privilege.Policies {
		id := p.Identity
		id.Generation = 0 // an edit of another section must not change this revision
		parts = append(parts, privilegePart{id, p.Mode, p.Privilege})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Identity.UID < parts[j].Identity.UID })
	s.privilege.Revision = digest(parts)
	for _, p := range plan.Policies {
		if p.Exec.Default == "" {
			continue
		}
		e := p
		e.Privilege = nil
		s.exec.Policies = append(s.exec.Policies, e)
		execParts = append(execParts, execPart{p.Identity, p.Mode, p.RootRole, p.Exec})
	}
	if len(execParts) > 0 {
		s.exec.Revision = digest(execParts)
	}
	return s, nil
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
	old := s.active[k]
	want, err := split(plan)
	if err != nil {
		return ReplaceResult{}, err
	}
	if old.execOnly() && want.execOnly() {
		r, err := s.exec.Replace(ctx, binding, plan)
		if r.Committed {
			s.active[k] = want
		}
		return r, err
	}
	if s.privilege == nil {
		return ReplaceResult{}, fmt.Errorf("privilege sections are unsupported: no privilege image configured")
	}

	e := apply(ctx, s.exec, binding, old.exec, want.exec)
	if !e.committed {
		return ReplaceResult{ProtectionUnconfirmed: e.unconfirmed}, fmt.Errorf("exec section: %w", e.err)
	}
	oldPrivilege := old.privilege
	if old.privilegeCleanup && oldPrivilege.Revision == "" {
		oldPrivilege.Revision = "cleanup" // forces a privilege Withdraw retry
	}
	p := apply(ctx, s.privilege, binding, oldPrivilege, want.privilege)
	if !p.committed {
		// Return exec to its previous plan.
		back := apply(ctx, s.exec, binding, want.exec, old.exec)
		return ReplaceResult{ProtectionUnconfirmed: e.unconfirmed || p.unconfirmed || back.unconfirmed || !back.committed},
			errors.Join(fmt.Errorf("privilege section: %w", p.err), back.err)
	}
	want.privilegeCleanup = want.privilege.Revision == "" && p.err != nil
	s.active[k] = want
	return ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: e.unconfirmed || p.unconfirmed}, errors.Join(e.err, p.err)
}

func (s *SectionBackend) Withdraw(ctx context.Context, binding Binding) (WithdrawResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindingKey(binding)
	old := s.active[k]
	if old.execOnly() {
		r, err := s.exec.Withdraw(ctx, binding)
		if r.Committed {
			delete(s.active, k)
		}
		return r, err
	}
	e, eerr := s.exec.Withdraw(ctx, binding)
	p, perr := s.privilege.Withdraw(ctx, binding)
	result := WithdrawResult{
		Committed: e.Committed && p.Committed,
		// One section removed and the other not: the old protection is gone.
		ProtectionUnconfirmed: e.ProtectionUnconfirmed || p.ProtectionUnconfirmed || e.Committed != p.Committed,
	}
	switch {
	case result.Committed && perr != nil:
		s.active[k] = sectionPlans{privilegeCleanup: true}
	case result.Committed:
		delete(s.active, k)
	case e.Committed:
		old.exec = Plan{}
		s.active[k] = old
	}
	return result, errors.Join(eerr, perr)
}

// Attest checks each section that is active for the binding.
func (s *SectionBackend) Attest(ctx context.Context, binding Binding, revision string) error {
	s.mu.Lock()
	plans, ok := s.active[bindingKey(binding)]
	s.mu.Unlock()
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
	for _, section := range []struct {
		backend Backend
		plan    Plan
	}{{s.exec, plans.exec}, {s.privilege, plans.privilege}} {
		if section.plan.Revision == "" {
			continue
		}
		a, isAttester := section.backend.(ProtectionAttester)
		if !isAttester {
			errs = append(errs, fmt.Errorf("backend cannot attest"))
			continue
		}
		errs = append(errs, a.Attest(ctx, binding, section.plan.Revision))
	}
	return errors.Join(errs...)
}

func (s *SectionBackend) Close(ctx context.Context) error {
	var errs []error
	for _, backend := range []Backend{s.exec, s.privilege} {
		if c, ok := backend.(interface{ Close(context.Context) error }); ok {
			errs = append(errs, c.Close(ctx))
		}
	}
	return errors.Join(errs...)
}
