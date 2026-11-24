package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// Section names of the node-wide section backends.
const (
	SectionPrivilege = "privilege"
	SectionNetwork   = "network"
	SectionFile      = "file"
)

// SectionBackend drives one backend per policy section.
//
// A binding whose old and new plans have only exec sections goes straight to
// the exec backend, unchanged. Otherwise the plan is split into an exec plan
// and one plan per other section (privilege, network, file), each with its own
// revision. When no policy object holds exec and another section, the exec
// plan and its revision are what the controller gives the exec policies alone,
// so adding, editing or removing a privilege or network policy does not restart
// exec. When one object holds both, its generation is part of the exec revision
// (as in the exec-only path): an edit of only its other section restarts exec
// once. This is a known limit; the generation must stay in the plan for status
// staleness.
//
// Commit follows the Backend contract of each section: a section that returns
// Committed=true is committed, even with a cleanup error. A section that does
// not commit stays on its previous plan; the others still move (see Replace).
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
	// failing holds the bindings (bindingKey) whose last Replace or
	// Withdraw of this section did not commit; podFailed: the last BindPods
	// of this section failed. Settle waits for this section until both are
	// clear; other sections settle on their own.
	failing   map[string]bool
	podFailed bool
}

// track records, per section, whether the binding's last call committed.
func (s *SectionBackend) track(k string, failed []bool) {
	for i, sec := range s.sections {
		switch {
		case failed[i]:
			if sec.failing == nil {
				sec.failing = map[string]bool{}
			}
			sec.failing[k] = true
		default:
			delete(sec.failing, k)
		}
	}
}

// sectionParts lists the sections next to exec, in SectionBackend order.
var sectionParts = []struct {
	name  string
	part  func(CompiledPolicy) any
	strip func(*CompiledPolicy)
}{
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
	{name: SectionFile, part: func(p CompiledPolicy) any {
		if p.File == nil {
			return nil
		}
		return p.File
	}, strip: func(p *CompiledPolicy) { p.File = nil }},
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
// network and file sections are unavailable until WithNetwork and WithFile set
// them.
func NewSectionBackend(exec, privilege Backend, unavailable error) (*SectionBackend, error) {
	if exec == nil {
		return nil, fmt.Errorf("exec backend is required")
	}
	s := &SectionBackend{exec: exec, active: map[string]sectionPlans{}}
	for _, part := range sectionParts {
		s.sections = append(s.sections, &section{name: part.name, part: part.part, strip: part.strip})
	}
	s.set(SectionPrivilege, privilege, unavailable, "PrivilegeNotConfigured", "no privilege gadget image is configured")
	s.set(SectionNetwork, nil, nil, "NetworkNotConfigured", "no network gadget image is configured")
	s.set(SectionFile, nil, nil, "FileNotConfigured", "no file gadget image is configured")
	return s, nil
}

// WithNetwork sets the network section backend. When network is nil,
// unavailable says why (nil means no network image is configured).
func (s *SectionBackend) WithNetwork(network Backend, unavailable error) *SectionBackend {
	s.set(SectionNetwork, network, unavailable, "NetworkNotConfigured", "no network gadget image is configured")
	return s
}

// WithFile sets the file section backend. When file is nil, unavailable says
// why (nil means no file image is configured).
func (s *SectionBackend) WithFile(file Backend, unavailable error) *SectionBackend {
	s.set(SectionFile, file, unavailable, "FileNotConfigured", "no file gadget image is configured")
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
		if sec.name != name {
			continue
		}
		return sec.unavailable
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

// withFailing marks for cleanup each section whose last call for the binding
// failed with no committed plan: the section may hold the plan it was asked
// for (and a reserved slot), so a plan that drops the section, or a
// Withdraw, must still reach it. Runs under mu.
func (s *SectionBackend) withFailing(k string, p sectionPlans) sectionPlans {
	var cleanup []bool
	for i, sec := range s.sections {
		if sec.failing[k] && p.other[i].Revision == "" && !p.cleanup[i] {
			if cleanup == nil {
				cleanup = append([]bool(nil), p.cleanup...)
			}
			cleanup[i] = true
		}
	}
	if cleanup != nil {
		p.cleanup = cleanup
	}
	return p
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
// a backend that loads its gadget before the first plan (privilege, network)
// does not load it for a policy of another section.
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
			if clearer, ok := preparer.(PreparedClearer); ok && sec.prepared {
				// The section has just become inactive: drop its prepared
				// set once, without starting an instance.
				errs = append(errs, clearer.ClearPrepared(ctx))
			}
			sec.prepared = false
			continue
		}
		sec.prepared = true
		errs = append(errs, preparer.Prepare(ctx, plans))
	}
	return errors.Join(errs...)
}

// BindPods passes the pod bindings to every available section backend that
// can bind pod cgroups. Each section binds a pod only when the pod plan has
// policies of that section (see Controller.PodPlans).
func (s *SectionBackend) BindPods(ctx context.Context, pods []PodBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, sec := range s.sections {
		if binder, ok := sec.backend.(PodBinder); ok && sec.unavailable == nil {
			err := binder.BindPods(ctx, pods)
			sec.podFailed = err != nil
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// gatePlan returns the policies of plan that have the section, and whether
// one of them is Strict (enforce mode).
func (sec *section) gatePlan(plan Plan) (has, strict bool) {
	for _, p := range plan.Policies {
		if sec.part(p) != nil {
			has, strict = true, strict || p.Mode == api.ModeEnforce
		}
	}
	return has, strict
}

// gate returns the section's pod gate, or why it has none (an unavailable
// section, or a backend without one).
func (sec *section) gate() (PodGate, error) {
	if sec.unavailable != nil {
		return nil, sec.unavailable
	}
	gate, ok := sec.backend.(PodGate)
	if !ok {
		return nil, &EnforcementUnavailableError{Section: sec.name, Reason: "NoPodGate", Detail: "the section backend cannot mark pods"}
	}
	return gate, nil
}

// MarkPod marks the pod in each section whose policies its plan has
// (PodGate.MarkPod). An unavailable section is a failed result: the caller
// decides by the section's class.
func (s *SectionBackend) MarkPod(ctx context.Context, pod PodBinding, seq Seq) []PodSectionResult {
	return s.eachGateSection(pod.Plan, func(gate PodGate) error { return gate.MarkPod(ctx, pod, seq) })
}

// EnsurePodBound moves the pod to its plan's slot in each section whose
// policies plan has (PodGate.EnsurePodBound).
func (s *SectionBackend) EnsurePodBound(ctx context.Context, uid types.UID, plan Plan) []PodSectionResult {
	return s.eachGateSection(plan, func(gate PodGate) error { return gate.EnsurePodBound(ctx, uid) })
}

func (s *SectionBackend) eachGateSection(plan Plan, call func(PodGate) error) []PodSectionResult {
	var out []PodSectionResult
	for _, sec := range s.sections {
		has, strict := sec.gatePlan(plan)
		if !has {
			continue
		}
		r := PodSectionResult{Section: sec.name, Strict: strict}
		gate, err := sec.gate()
		if err == nil {
			err = call(gate)
		}
		r.Err = err
		out = append(out, r)
	}
	return out
}

// ConfirmPod reports, for every section whose policies plan has, whether the
// pod is protected as plan asks (PodGate.ConfirmPod). An unavailable section,
// or one without a pod gate, is Unavailable: never confirmed.
func (s *SectionBackend) ConfirmPod(uid types.UID, cgroupID uint64, plan Plan) []PodSectionConfirmation {
	var out []PodSectionConfirmation
	for _, sec := range s.sections {
		has, strict := sec.gatePlan(plan)
		if !has {
			continue
		}
		gate, err := sec.gate()
		if err != nil {
			out = append(out, PodSectionConfirmation{Section: sec.name, State: PodSectionUnavailable, Strict: strict, Reason: err.Error()})
			continue
		}
		out = append(out, gate.ConfirmPod(uid, cgroupID, plan))
	}
	return out
}

// ReleasePod removes the pod's binding from every available section that
// has a pod gate (PodGate.ReleasePod), whatever its plan.
func (s *SectionBackend) ReleasePod(ctx context.Context, uid types.UID, cgroupID uint64) error {
	var errs []error
	for _, sec := range s.sections {
		if gate, err := sec.gate(); err == nil {
			errs = append(errs, gate.ReleasePod(ctx, uid, cgroupID))
		}
	}
	return errors.Join(errs...)
}

// BindPodsAt is BindPods with the sequence of the classification that gave
// pods (PodGate.BindPodsAt), for every available section with a pod gate.
func (s *SectionBackend) BindPodsAt(ctx context.Context, pods []PodBinding, seq Seq) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, sec := range s.sections {
		if gate, err := sec.gate(); err == nil {
			err := gate.BindPodsAt(ctx, pods, seq)
			// A stale write is ordinary race traffic: refused, reported,
			// but it does not hold the section's Settle back.
			sec.podFailed = err != nil && !onlyStale(err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// onlyStale reports whether every leaf error under err is ErrStaleSequence:
// it descends joined errors and single wrappers alike.
func onlyStale(err error) bool {
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			if inner != nil && !onlyStale(inner) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); inner != nil {
			return onlyStale(inner)
		}
	}
	return errors.Is(err, ErrStaleSequence) // a leaf: no wrapper left
}

// SetStartGate turns the start gate's rules on in every section with a pod
// gate (PodGate.SetStartGate).
func (s *SectionBackend) SetStartGate(enabled bool) {
	for _, sec := range s.sections {
		if gate, ok := sec.backend.(PodGate); ok {
			gate.SetStartGate(enabled)
		}
	}
}

// SetNRISynced records in every section with a pod gate that the NRI plugin
// completed Synchronize on connection epoch, with the cgroups it proved
// Unselected or absent (PodGate.SetNRISynced).
func (s *SectionBackend) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	for _, sec := range s.sections {
		if gate, ok := sec.backend.(PodGate); ok {
			gate.SetNRISynced(epoch, proven)
		}
	}
}

// SetNRIDisconnected records in every section with a pod gate that the NRI
// plugin's connection epoch closed (PodGate.SetNRIDisconnected).
func (s *SectionBackend) SetNRIDisconnected(epoch uint64) {
	for _, sec := range s.sections {
		if gate, ok := sec.backend.(PodGate); ok {
			gate.SetNRIDisconnected(epoch)
		}
	}
}

// SetCgroupGone sets the cgroup-gone proof in every section with a pod gate
// (PodGate.SetCgroupGone).
func (s *SectionBackend) SetCgroupGone(gone func(cgroup uint64) bool) {
	for _, sec := range s.sections {
		if gate, ok := sec.backend.(PodGate); ok {
			gate.SetCgroupGone(gone)
		}
	}
}

// UnmarkPod removes the pod's start gate binding from every available
// section with a pod gate (PodGate.UnmarkPod), whatever its plan.
func (s *SectionBackend) UnmarkPod(ctx context.Context, uid types.UID, cgroupID uint64, seq Seq) error {
	var errs []error
	for _, sec := range s.sections {
		if gate, err := sec.gate(); err == nil {
			errs = append(errs, gate.UnmarkPod(ctx, uid, cgroupID, seq))
		}
	}
	return errors.Join(errs...)
}

// BindsPods reports whether an available section backend can bind pod cgroups.
func (s *SectionBackend) BindsPods() bool {
	for _, sec := range s.sections {
		if _, ok := sec.backend.(PodBinder); ok && sec.unavailable == nil {
			return true
		}
	}
	return false
}

// SnapshotComplete is called after a refresh whose binding snapshot was
// complete. bindings is that snapshot: a failed binding that is no longer in
// it (its container is gone) stops holding its section back. Each section
// backend that observes snapshots is told (SnapshotObserver).
func (s *SectionBackend) SnapshotComplete(bindings []Binding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	present := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		present[bindingKey(b)] = true
	}
	for _, sec := range s.sections {
		for k := range sec.failing {
			if !present[k] {
				delete(sec.failing, k)
			}
		}
		if observer, ok := sec.backend.(SnapshotObserver); ok {
			observer.SnapshotComplete()
		}
	}
}

// Settle passes a converged refresh to each section backend that settles. A
// section settles when every binding and pod binding of its own committed;
// a failing binding of another section, or a failed status write, does not
// hold it back.
func (s *SectionBackend) Settle(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, sec := range s.sections {
		if settler, ok := sec.backend.(Settler); ok && len(sec.failing) == 0 && !sec.podFailed {
			errs = append(errs, settler.Settle(ctx))
		}
	}
	return errors.Join(errs...)
}

// Adopted returns the adopted slots of every available section backend that
// reports them.
func (s *SectionBackend) Adopted() []AdoptedSlot {
	var out []AdoptedSlot
	for _, sec := range s.sections {
		if reporter, ok := sec.backend.(AdoptionReporter); ok && sec.unavailable == nil {
			out = append(out, reporter.Adopted()...)
		}
	}
	return out
}

// BoundPodPlans returns the plans bound to pod cgroups by every available
// section backend that reports them.
func (s *SectionBackend) BoundPodPlans() (confirmed, faulted []Plan) {
	for _, sec := range s.sections {
		if reporter, ok := sec.backend.(PodPlanReporter); ok && sec.unavailable == nil {
			c, f := reporter.BoundPodPlans()
			confirmed, faulted = append(confirmed, c...), append(faulted, f...)
		}
	}
	return confirmed, faulted
}

// RuntimeHelperStatus joins the runtime helper reports of the sections that
// have one (the arming sections). One unreadable count makes the total
// unknown.
func (s *SectionBackend) RuntimeHelperStatus() (enabled bool, plans []Plan, exempt uint64, err error) {
	var errs []error
	for _, sec := range s.sections {
		reporter, ok := sec.backend.(RuntimeHelperReporter)
		if !ok || sec.unavailable != nil {
			continue
		}
		on, p, n, e := reporter.RuntimeHelperStatus()
		if !on {
			continue
		}
		enabled, plans, exempt = true, append(plans, p...), exempt+n
		if e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sec.name, e))
		}
	}
	return enabled, plans, exempt, errors.Join(errs...)
}

// Exec returns the exec section backend.
func (s *SectionBackend) Exec() Backend { return s.exec }

// sectionRevision is the revision of one section of a plan (part selects
// it): a section compiler reads each policy's identity, mode and section,
// so it digests those, with Generation zeroed (an edit of another section
// must not change this revision), sorted by UID. "" when no policy has the
// section. split and SectionDigest use it.
func sectionRevision(policies []CompiledPolicy, part func(CompiledPolicy) any) string {
	type sectionPart struct {
		Identity PolicyIdentity
		Mode     api.PolicyMode
		Section  any
	}
	var parts []sectionPart
	for _, p := range policies {
		if section := part(p); section != nil {
			id := p.Identity
			id.Generation = 0
			parts = append(parts, sectionPart{id, p.Mode, section})
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Slice(parts, func(a, b int) bool { return parts[a].Identity.UID < parts[b].Identity.UID })
	return digest(parts)
}

func (s *SectionBackend) split(plan Plan) sectionPlans {
	out := s.normalize(sectionPlans{revision: plan.Revision})
	found := false
	for i, sec := range s.sections {
		for _, p := range plan.Policies {
			if sec.part(p) != nil {
				out.other[i].Policies = append(out.other[i].Policies, p)
			}
		}
		if len(out.other[i].Policies) == 0 {
			continue
		}
		found = true
		out.other[i].Revision = sectionRevision(out.other[i].Policies, sec.part)
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
	committed, unconfirmed, ioUringHeld bool
	err                                 error
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
		return sectionResult{committed, r.ProtectionUnconfirmed, r.IoUringHeld, err}
	default:
		r, err := backend.Withdraw(ctx, binding)
		if !r.Committed && err == nil {
			err = fmt.Errorf("withdraw not committed")
		}
		return sectionResult{r.Committed, r.ProtectionUnconfirmed, false, err}
	}
}

func (s *SectionBackend) Replace(ctx context.Context, binding Binding, plan Plan) (ReplaceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindingKey(binding)
	old := s.withFailing(k, s.normalize(s.active[k]))
	want := s.split(plan)
	// A partial commit (revision "") stays unconfirmed until a Replace
	// moves every section.
	_, exists := s.active[k]
	partial := exists && old.revision == ""
	if old.execOnly() && want.execOnly() {
		s.track(k, make([]bool, len(s.sections))) // no section is involved
		r, err := s.exec.Replace(ctx, binding, plan)
		if r.Committed {
			s.active[k] = want
		} else {
			r.ProtectionUnconfirmed = r.ProtectionUnconfirmed || partial
		}
		return r, err
	}
	// Each section moves on its own. A section that fails (unavailable, a
	// refused exec plan, a slot that does not fit, a failed bind) stays on
	// its last-good plan, and its error names it; it never blocks another
	// section. The binding attests only when every section runs the desired
	// plan. Known limit: when the new plan moves a deny from one section to
	// another (a privilege rule that only audits a mount, under a Strict file
	// section whose root barrier denies it), a failure of the receiving
	// section leaves the call allowed until a retry; status reports the
	// binding unconfirmed meanwhile.
	next := old
	next.other, next.cleanup = append([]Plan(nil), old.other...), append([]bool(nil), old.cleanup...)
	unconfirmed, moved, ioUringHeld := false, false, false
	var failed, errs []error
	skip := make([]bool, len(s.sections))
	sectionFailed := make([]bool, len(s.sections))
	defer func() { s.track(k, sectionFailed) }()
	for i, sec := range s.sections {
		if sec.backend == nil && want.other[i].Revision != "" {
			skip[i] = true
			failed = append(failed, sec.unavailable)
		}
	}
	// Prepare first: a section's slot is ready before exec commits, so its
	// live bind below is a map write.
	for i, sec := range s.sections {
		preparer, ok := sec.backend.(ReplacePreparer)
		if skip[i] || !ok || want.other[i].Revision == "" || want.other[i].Revision == old.other[i].Revision {
			continue
		}
		if err := preparer.PrepareReplace(ctx, binding, want.other[i]); err != nil {
			skip[i], sectionFailed[i] = true, true
			failed = append(failed, fmt.Errorf("%s section: %w", sec.name, err))
		}
	}
	// A removed section is withdrawn first: also when its last call for this
	// container failed (no committed plan, but the section may hold its
	// desired plan, and a reserved slot).
	for i, sec := range s.sections {
		oldPlan := old.other[i]
		if old.cleanup[i] && oldPlan.Revision == "" {
			oldPlan.Revision = "cleanup" // forces a Withdraw retry
		}
		if sec.backend == nil || want.other[i].Revision != "" || oldPlan.Revision == "" {
			continue
		}
		skip[i] = true // done here
		r := apply(ctx, sec.backend, binding, oldPlan, want.other[i])
		unconfirmed = unconfirmed || r.unconfirmed
		if !r.committed {
			sectionFailed[i] = true
			failed = append(failed, fmt.Errorf("%s section: %w", sec.name, r.err))
			continue
		}
		moved = moved || old.other[i].Revision != ""
		next.other[i], next.cleanup[i] = Plan{}, r.err != nil
		errs = append(errs, r.err)
	}
	e := apply(ctx, s.exec, binding, old.exec, want.exec)
	unconfirmed = unconfirmed || e.unconfirmed
	if e.committed {
		moved = moved || want.exec.Revision != old.exec.Revision
		next.exec = want.exec
		errs = append(errs, e.err)
	} else {
		failed = append(failed, fmt.Errorf("exec section: %w", e.err))
	}
	for i, sec := range s.sections {
		if sec.backend == nil || skip[i] {
			continue
		}
		oldPlan := old.other[i]
		if old.cleanup[i] && oldPlan.Revision == "" {
			oldPlan.Revision = "cleanup" // forces a Withdraw retry
		}
		r := apply(ctx, sec.backend, binding, oldPlan, want.other[i])
		unconfirmed = unconfirmed || r.unconfirmed
		ioUringHeld = ioUringHeld || r.ioUringHeld
		if !r.committed {
			sectionFailed[i] = true
			failed = append(failed, fmt.Errorf("%s section: %w", sec.name, r.err))
			continue
		}
		moved = moved || want.other[i].Revision != old.other[i].Revision
		next.other[i] = want.other[i]
		next.cleanup[i] = want.other[i].Revision == "" && r.err != nil
		errs = append(errs, r.err)
	}
	if len(failed) == 0 {
		next.revision = want.revision
		s.active[k] = next
		return ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: unconfirmed, IoUringHeld: ioUringHeld}, errors.Join(errs...)
	}
	err := errors.Join(append(failed, errs...)...)
	if !moved {
		// Nothing moved: the binding keeps its last-good plan (a new
		// binding keeps none).
		if exists {
			next.revision = old.revision
			s.active[k] = next
		}
		return ReplaceResult{ProtectionUnconfirmed: unconfirmed || partial}, err
	}
	// In part: the sections that moved enforce the desired plan, the others
	// their last-good plan. Committed, so the caller owns (and later
	// withdraws) the binding, but never confirmed.
	next.revision = "" // Attest fails until every section runs the desired plan
	s.active[k] = next
	return ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: true, IoUringHeld: ioUringHeld}, err
}

func (s *SectionBackend) Withdraw(ctx context.Context, binding Binding) (WithdrawResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := bindingKey(binding)
	old := s.withFailing(k, s.normalize(s.active[k]))
	if old.execOnly() {
		s.track(k, make([]bool, len(s.sections))) // no section is involved
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
	sectionFailed := make([]bool, len(s.sections))
	defer func() { s.track(k, sectionFailed) }()
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
			sectionFailed[i] = true
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

// SampleRates samples the reporting counters of every section that has them.
func (s *SectionBackend) SampleRates(now time.Time) {
	for _, sec := range s.sections {
		if r, ok := sec.backend.(RateReporter); ok && sec.unavailable == nil {
			r.SampleRates(now)
		}
	}
}

// PolicyRates joins the reports of the sections that have the policy in a
// slot: Degraded or NotReady when any is, Unknown when any is; the suppressed
// verdicts add up.
func (s *SectionBackend) PolicyRates(uid types.UID, now time.Time) (RateReport, bool) {
	var joined RateReport
	var unknown []error
	var messages, notes, lossUnknown []string
	found := false
	for _, sec := range s.sections {
		r, ok := sec.backend.(RateReporter)
		if !ok || sec.unavailable != nil {
			continue
		}
		rep, ok := r.PolicyRates(uid, now)
		if !ok {
			continue
		}
		found = true
		joined.Degraded = joined.Degraded || rep.Degraded
		joined.NotReady = joined.NotReady || rep.NotReady
		if rep.Unknown != nil {
			unknown = append(unknown, rep.Unknown)
		}
		messages = append(messages, rep.Message)
		if rep.Suppressed > 0 {
			joined.Suppressed += rep.Suppressed
			notes = append(notes, rep.SuppressedNote)
		}
		if rep.SuppressedUnknown != "" {
			lossUnknown = append(lossUnknown, rep.SuppressedUnknown)
		}
	}
	joined.Unknown = errors.Join(unknown...)
	joined.Message = strings.Join(messages, "; ")
	joined.SuppressedNote = strings.Join(notes, ", ")
	joined.SuppressedUnknown = strings.Join(lossUnknown, ", ")
	return joined, found
}

// RestartSurvival lists, per section with restart survival on, whether its
// enforcement survives a node-agent restart. Exec enforcement is not pinned:
// it is listed as not surviving whenever the slot sections are.
func (s *SectionBackend) RestartSurvival() []SectionRestart {
	var out []SectionRestart
	for _, sec := range s.sections {
		if r, ok := sec.backend.(RestartReporter); ok && sec.unavailable == nil {
			if st, ok := r.RestartStatus(); ok {
				out = append(out, st)
			}
		}
	}
	if len(out) > 0 {
		out = append(out, SectionRestart{Section: "exec", Err: errExecNotPinned})
	}
	return out
}

// errExecNotPinned: exec enforcement is not pinned, so a node-agent restart
// stops it until the new node-agent binds again.
var errExecNotPinned = errors.New("exec enforcement is not pinned: it stops during a node-agent restart until the new node-agent binds")
