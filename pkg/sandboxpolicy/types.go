// Package sandboxpolicy selects and compiles Kubernetes sandbox policies. It does
// not attach programs: Backend owns kernel capability validation and lifecycle.
package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// Binding is an immutable runtime identity. CgroupID must be verified by the
// backend against the live container, not inferred from pod metadata.
type Binding struct {
	Runtime        string
	CgroupPath     string
	PID            uint32
	MountNamespace uint64
	ContainerID    string
	CgroupID       uint64
	PodUID         types.UID
	Namespace      string
	PodName        string
	ContainerName  string
	// Kind is regular, init, or ephemeral. Wildcard policy selectors match regular only.
	Kind            string
	PodLabels       map[string]string
	NamespaceLabels map[string]string
}

// BindingPendingError accompanies a selected runtime snapshot while live
// Kubernetes containers that a policy selects, or may select, are not yet
// correlated with a running node pod (kubelet has not reported them Running).
// Returned together with the correlated bindings, it is non-fatal: Refresh binds
// those as usual, and every policy reports Ready False with reason
// BindingPending until a snapshot has no pending container. Returned without
// bindings, it is an ordinary failed snapshot.
type BindingPendingError struct {
	// Containers counts the selected, uncorrelated live containers on the node.
	Containers int
}

func (e *BindingPendingError) Error() string {
	return fmt.Sprintf("binding pending: %d selected live container(s) not yet correlated with a running node pod", e.Containers)
}

type PolicyIdentity struct {
	Kind       string    `json:"kind"`
	Namespace  string    `json:"namespace,omitempty"`
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
}

// CompiledPolicy keeps policy-local role namespaces, mode overrides and defaults
// separate. Backends must implement deny-wins across policies, not first-match.
type CompiledPolicy struct {
	Identity PolicyIdentity  `json:"identity"`
	Revision string          `json:"revision"`
	Mode     api.PolicyMode  `json:"mode"`
	RootRole string          `json:"rootRole"`
	Exec     api.ExecSection `json:"exec"`
	// Privilege is nil when the policy has no privilege section.
	Privilege *api.PrivilegeSection `json:"privilege,omitempty"`
	// Network is nil when the policy has no network section.
	Network *NetworkPlan `json:"network,omitempty"`
	// File is nil when the policy has no file section.
	File *FilePlan `json:"file,omitempty"`
}

type Plan struct {
	Revision string           `json:"revision"`
	Policies []CompiledPolicy `json:"policies"`
}

// ReplaceResult distinguishes a failed candidate from a committed candidate whose
// old-instance cleanup failed. Committed results MUST identify the desired plan's
// exact revision. An error does not imply rollback after the commit boundary.
type ReplaceResult struct {
	Committed      bool
	ActiveRevision string
	// ProtectionUnconfirmed indicates externally lost/uncertain health or identity
	// of owned enforcement, not an ordinary rejected candidate. Ownership remains
	// for cleanup, but callers MUST NOT claim active or last-good protection. This
	// flag does not relax the requirement to preserve healthy old enforcement when
	// a candidate fails. A confirmed candidate/re-attestation clears it.
	ProtectionUnconfirmed bool
	// IoUringHeld: an Audit binding whose tasks held io_uring rings opened
	// before it (a Strict one is refused instead). Reported in status, never
	// blocking.
	IoUringHeld bool
}

// WithdrawResult records the point after which this binding is no longer
// protected. Committed=true is required on success and after removal even if
// subsequent resource cleanup fails.
type WithdrawResult struct {
	Committed bool
	// A failed drain/retirement may leave membership present without healthy
	// admission. Do not report that retained owner as confirmed last-good.
	ProtectionUnconfirmed bool
}

// Backend owns candidate readiness, immutable replacement and cleanup. Before
// commit, failure MUST leave the previous plan enforced and clean up the candidate.
// After commit, return Committed=true even if retiring old instances fails; the
// new plan is active but reconciliation remains NotReady until cleanup succeeds.
// Same-plan Replace retries must safely finish cleanup without resetting roles or
// creating gaps. Success requires Committed=true and ActiveRevision=Plan.Revision.
// Temporary overlap may overblock, but never introduce an enforcement gap.
// Unsupported predicates, limits and incomplete identities must return errors.
// Withdraw is idempotent and removes only this exact container/cgroup identity;
// stale deletion must never remove a newer registration. Before commit, errors
// retain enforcement; after commit, errors MUST return Committed=true. Repeated
// calls after removal finish cleanup without touching newer runtime identities.
type Backend interface {
	Replace(context.Context, Binding, Plan) (ReplaceResult, error)
	Withdraw(context.Context, Binding) (WithdrawResult, error)
}

// ProtectionAttester optionally verifies an already-owned exact binding/revision.
// It must not install, update, resume, abort or publish any policy. Unsupported
// attestation leaves ownership retained but protection unconfirmed during discovery
// uncertainty; only an authoritative snapshot may authorize reconciliation again.
type ProtectionAttester interface {
	Attest(context.Context, Binding, string) error
}

// ReplacePreparer optionally does the part of a Replace that can fail without
// changing any binding (for example a new policy slot in a node instance), so
// that a Replace with the same plan right after it is a live map write.
// SectionBackend prepares the privilege section before it commits exec.
type ReplacePreparer interface {
	PrepareReplace(ctx context.Context, binding Binding, plan Plan) error
}

// SlotPreparer optionally prepares enforcement for pods scheduled to this node
// before their containers start. Each plan is what a container of such a pod
// will get. It is a hint: a later Replace must still work without it.
type SlotPreparer interface {
	Prepare(context.Context, []Plan) error
}

// PreparedClearer optionally drops the prepared set of a SlotPreparer whose
// section has no active policy. Unlike Prepare with no plans, it never starts
// an instance.
type PreparedClearer interface {
	ClearPrepared(context.Context) error
}

// SectionPreparer is a SlotPreparer that drives several sections.
// PrepareSections prepares only the sections in active (nil: every section).
type SectionPreparer interface {
	PrepareSections(ctx context.Context, plans []Plan, active map[string]bool) error
}

// PodBinding places the pod-level cgroup of a pod scheduled to this node in
// the plan that every container of the pod gets. Container cgroups are created
// under the pod cgroup, so a container is judged from its first exec, before
// its own binding exists. The container binding still decides once it exists.
type PodBinding struct {
	PodUID     types.UID
	Namespace  string
	PodName    string
	CgroupID   uint64
	CgroupPath string
	Plan       Plan
	// ContainersStarted: a container of the pod exists already (the
	// container collection knows it). A pod binding does not arm the tasks
	// already in the pod cgroup, so such a pod gets no new pod binding, and a
	// pod binding carried into a new instance is not confirmed. Its
	// containers rely on their own container bindings.
	ContainersStarted bool
}

// PodBinder optionally binds pod cgroups. BindPods receives the complete set:
// a pod binding that is not in it is removed. A pod given with an empty Plan
// keeps its current binding (its input is incomplete). Like SlotPreparer, it is a hint
// that changes no container binding.
type PodBinder interface {
	BindPods(context.Context, []PodBinding) error
}

// ErrStaleSequence: a pod's mark was written by a newer (or incomparable)
// classification than the one that asks for this write, so the write is
// refused. It is returned, never skipped silently.
var ErrStaleSequence = errors.New("stale sequence: a newer classification wrote this pod's mark")

// ErrPolicyEntry: the pod cgroup already holds an entry on a policy slot
// that a previous run left (adopted), of a class at least as strict as the
// plan asks. PodGate.MarkPod never writes a pending mark over it. For the
// caller (S3) such a pod is not failed: the entry protects it until BindPods
// moves it to its plan. It never admits a container by itself: a Strict
// create needs PodGate.ConfirmPod to answer Confirmed, or Pending with
// Strict. Any other entry that a mark must not replace (nothing bound after
// a failed bind, another plan, a looser class) is an ordinary error.
var ErrPolicyEntry = errors.New("the pod cgroup holds an entry on a policy slot; a pending mark never replaces it")

// PodSectionState is how far one section protects a pod (PodGate.ConfirmPod).
type PodSectionState int

const (
	// PodSectionFaulted: not protected as the plan asks (no record, another
	// plan or cgroup, an instance or slot fault, a read-back that does not
	// match). The zero value: never confirmed by default.
	PodSectionFaulted PodSectionState = iota
	// PodSectionPending: the pod's cgroup carries the pending mark of the
	// plan, read back from the kernel, but not its policy slot yet. A Strict
	// mark denies; an Audit one allows and counts (degraded accounting).
	PodSectionPending
	// PodSectionConfirmed: bound to the plan's slot, read back from the
	// kernel, the slot healthy.
	PodSectionConfirmed
	// PodSectionUnavailable: the section cannot be enforced (not
	// configured, or no pod gate). Never confirmed.
	PodSectionUnavailable
)

// PodSectionConfirmation is one section's answer for a pod. Strict is the
// class of the section's policies in the caller's plan.
type PodSectionConfirmation struct {
	Section string
	State   PodSectionState
	Strict  bool
	Reason  string
}

// PodSectionResult is one section's result of a pod gate write.
type PodSectionResult struct {
	Section string
	Strict  bool
	Err     error
}

// PodGate marks and binds one pod cgroup at a time for the NRI start gate.
// The mark is the pod cgroup's ordinary binding entry pointing at a slot that
// is never published (enforcement.PendingSlot): a Strict task under it is
// denied and an Audit task allowed and counted, until the pod is bound to its
// plan's slot. Writes are ordered per pod by Seq; a refused write returns
// ErrStaleSequence.
type PodGate interface {
	// MarkPod writes the pending mark of the pod's plan: absent to pending,
	// Audit-pending to Strict-pending, and a plan change of a pending mark
	// (newer or equal sequence); Strict-pending to Audit-pending only with a
	// newer sequence. It never writes over an entry on a policy slot and
	// never removes a mark: an adopted entry as strict as the plan is
	// ErrPolicyEntry, every other such entry another error. Neither admits
	// a create: a Strict create needs ConfirmPod to answer Confirmed, or
	// Pending with Strict. Restart survival must be on (the mark must
	// outlive node-agent).
	MarkPod(ctx context.Context, pod PodBinding, seq Seq) error
	// EnsurePodBound moves a pending pod to its record's own plan's slot
	// with one map write (sequence-neutral).
	EnsurePodBound(ctx context.Context, uid types.UID) error
	// ConfirmPod reports whether the pod is protected as plan asks.
	ConfirmPod(uid types.UID, cgroupID uint64, plan Plan) PodSectionConfirmation
	// UnmarkPod removes the pod's start gate binding (pending or bound)
	// because an authoritative classification at seq found it Unselected.
	// Only a strictly newer sequence removes it; otherwise
	// ErrStaleSequence; a retry at the sequence of an unmark that is still
	// pending (instance not ready) returns nil. With no record, it only
	// records the removal's order
	// (a later stale mark is refused); a previous run's mark on cgroupID is
	// never dropped by UnmarkPod, on any call: Synchronize's proof
	// (SetNRISynced), the gone proof or a committed entry decides it. A
	// released pod (its removal under way) returns nil.
	UnmarkPod(ctx context.Context, uid types.UID, cgroupID uint64, seq Seq) error
	// ReleasePod removes the pod's binding, pending or bound, whatever the
	// sequence: the pod's last sandbox is gone. With no record, it removes
	// only a pending mark a previous run left on cgroupID, never an entry on
	// a policy slot. cgroupID must be the sandbox's resolved pod cgroup.
	// Tombstone contract (S3): ReleasePod forgets the pod's order, so the
	// caller must tombstone the sandbox ID before calling it and refuse any
	// later MarkPod for that sandbox; a MarkPod in flight would otherwise
	// mark the released cgroup again.
	ReleasePod(ctx context.Context, uid types.UID, cgroupID uint64) error
	// BindPodsAt is PodBinder.BindPods with the sequence of the
	// classification that produced pods. A start gate pod missing from pods
	// is never removed for that reason (missing is not Unselected): only
	// ReleasePod, UnmarkPod, its cgroup's gone proof, or pods listing it
	// with a plan without this section remove it. A refused write to a
	// marked pod is an ErrStaleSequence error for that pod; the other pods
	// proceed.
	BindPodsAt(ctx context.Context, pods []PodBinding, seq Seq) error
	// SetStartGate turns the start gate's rules on (default off: main's
	// behaviour).
	SetStartGate(enabled bool)
	// SetNRISynced records that the NRI plugin completed Synchronize on
	// its connection epoch: proven holds the pod cgroups Synchronize proved
	// Unselected or absent (an Unknown pod's cgroup is never in it); nil
	// means synced with nothing proven. A completion older than the last
	// one, or at or below the last SetNRIDisconnected epoch, is stale and
	// ignored. With the gate on, an
	// adopted or old-set pending mark goes only when this run committed an
	// equal or stricter entry for its cgroup, the cgroup is gone, or it is
	// in proven.
	SetNRISynced(epoch uint64, proven map[uint64]bool)
	// SetNRIDisconnected records that connection epoch closed (pass the
	// dying connection's epoch): not synced until a later connection's
	// Synchronize completes.
	SetNRIDisconnected(epoch uint64)
	// SetCgroupGone sets the proof that a cgroup no longer exists, by
	// cgroup ID (default: never gone, so marks are kept). S3/S5 wiring
	// blocker: the gate must not be enabled before a real ID-based check
	// is wired here.
	SetCgroupGone(gone func(cgroup uint64) bool)
}

// Settler optionally runs after a refresh that converged: the configuration
// loaded, the snapshot was complete and every binding committed. A node
// backend with restart survival then drops the last-good state of the previous
// node-agent run.
type Settler interface {
	Settle(context.Context) error
}

// AdoptedSlot is a slot of the state a previous node-agent run left (restart
// survival) whose kernel bindings no container of this run took over yet: it
// still enforces the previous run's policies. Policies, Generation and Digest
// come from the previous run's manifest (empty when it had none).
type AdoptedSlot struct {
	Section    string
	Slot       uint32
	Generation uint64
	Digest     string
	Policies   []PolicyRevision
	Bindings   int
	// Degraded: the settle deadline passed and the section keeps adopted
	// bindings only for current Strict plans (fail closed).
	Degraded bool
	// LinkError: a link of a previous run's pinned set no longer runs its
	// program; the adopted state cannot be confirmed.
	LinkError error
	// Unreadable: a kept pinned set of the section could not be read (its
	// policies and bindings are not known); LinkError says why. Every policy
	// of the section reports it.
	Unreadable bool
	// PendingMark: the bindings are pod marks of the previous run
	// (enforcement.PendingSlot): they carry no policy; a Strict one denies
	// and an Audit one allows. Slot is PendingSlot and Policies is empty.
	PendingMark bool
}

// SectionRestart is whether a section's enforcement survives a node-agent
// restart (its instance is pinned on the host).
type SectionRestart struct {
	Section string
	Pinned  bool
	// Err: the last pin failed (the next restart would not keep enforcing).
	Err error
}

// RestartReporter optionally reports restart survival per section (ok false:
// restart survival is off for that section).
type RestartReporter interface {
	RestartStatus() (SectionRestart, bool)
}

// SnapshotObserver is told that the controller saw a complete binding
// snapshot and committed its plans: after it, a cgroup that has no plan of a
// section has no policy of that section (restart survival drops an adopted
// binding of such a cgroup at the settle deadline).
type SnapshotObserver interface {
	SnapshotComplete()
}

// AdoptionReporter optionally reports the adopted slots, for the
// AdoptedLastGood status condition.
type AdoptionReporter interface {
	Adopted() []AdoptedSlot
}

// PodPlanReporter optionally reports the plans of the pod cgroup bindings, so
// node status counts them like container bindings. confirmed are the plans
// that the witness counters prove: the pod was bound before its containers
// started and its slot has no fault. faulted are the plans whose slot has a
// fault, so their protection cannot be confirmed. A pod bound after its
// containers started is in neither: its containers rely on their own bindings.
type PodPlanReporter interface {
	BoundPodPlans() (confirmed, faulted []Plan)
}

// RuntimeHelperReporter reports the runtime helper exemption: whether the
// host operator enabled it, the plans of the pod bindings that carry it, and
// the execs it exempted on the node (err: unknown).
type RuntimeHelperReporter interface {
	RuntimeHelperStatus() (enabled bool, plans []Plan, exempt uint64, err error)
}

// SourceResolver reads ContainerProfile execs in the selected pod's namespace.
// It must return an error for missing/incomplete profiles; empty successful results
// mean a known complete profile with no execs. Rules retain their predicates.
// The caller invokes Controller.Reconcile when referenced profile content changes.
type SourceResolver interface {
	ResolveExecs(context.Context, string, string, string) ([]api.ExecRule, error)
}

type StatusWriter interface {
	WriteStatus(context.Context, *api.SandboxPolicyNodeStatus) error
}

type policyExecKey struct{}

// WithPolicyExec tells a StatusWriter whether the policy whose report it
// writes carries exec rules (an exec section or ContainerProfile sources).
// The controller sets it on every WriteStatus; exec-only node health (the
// shared exec engine's) applies only to such policies.
func WithPolicyExec(ctx context.Context, hasExec bool) context.Context {
	return context.WithValue(ctx, policyExecKey{}, hasExec)
}

// PolicyExecFrom returns what WithPolicyExec recorded; known is false when
// the caller did not say, and a writer must then treat the policy as an exec
// policy (fail-closed).
func PolicyExecFrom(ctx context.Context) (hasExec, known bool) {
	hasExec, known = ctx.Value(policyExecKey{}).(bool)
	return hasExec, known
}

// PolicyRevision identifies one immutable policy applied to a decision.
type PolicyRevision struct {
	Policy   PolicyIdentity
	Revision string
}

// RuleMatch records a reported match, not necessarily a decisive rule.
type RuleMatch struct {
	Policy   PolicyIdentity
	Revision string
	Name     string
	Origin   string   // Legacy scalar; use Origins for presence-aware provenance.
	Origins  []string `json:"origins"`
	Action   api.Action
	Mode     api.RuleMode
}

// Verdict is independent of observer trace_exec: denied attempts are not process
// creation events. Optional fields remain absent when the backend cannot know them.
type Verdict struct {
	// PolicySet contains every applied policy; Policy/Rule below are singular
	// only when attribution is unambiguous. Matches may be partial on faults.
	PolicySet []PolicyRevision
	Matches   []RuleMatch
	// MatchesComplete is false for legacy events and operational failures.
	MatchesComplete bool
	Time            time.Time
	Policy          PolicyIdentity
	// Revision is always the aggregate Plan.Revision, independent of singular
	// attribution. Policy-specific revisions belong to PolicySet and Matches.
	Revision       string
	Rule           string
	Origin         string   // Legacy scalar; use Origins for presence-aware provenance.
	Origins        []string `json:"origins"`
	Mode           api.RuleMode
	Verdict        api.Action
	WouldDeny      bool
	Reason         string
	ContainerID    string
	PodUID         types.UID
	BindingPID     uint32
	MountNamespace uint64
	CgroupID       uint64
	PID            uint32
	ParentPID      uint32
	UID            *uint32
	ActorPath      string
	TargetPath     string
	Argv           []string
	FromImage      *bool
	// Pass, ExecID, TaskCookie and LoadEpoch are present only on
	// shared-engine events (additive event ABI). Pass is the evaluated bprm
	// pass (absent for a fault); one exec's passes share ExecID, and
	// (LoadEpoch, TaskCookie, ExecID) is node-unique when TaskCookie is
	// present. LoadEpoch is the nonzero per-collection-load epoch: TaskCookie
	// restarts on every load, so it is never a key without LoadEpoch.
	Pass       *uint32
	ExecID     *uint64
	TaskCookie *uint64
	LoadEpoch  *uint64
	// ExecClass (1 Audit, 2 Strict), Scope (the route scope), Uncertain and
	// FactsUnknown (the unknown-fact bitmap) are also present only on
	// shared-engine events, so uncertain verdicts stay visible downstream.
	ExecClass    *uint32
	Scope        *uint64
	Uncertain    *bool
	FactsUnknown *uint32
}

type VerdictReceiver interface {
	ReportVerdict(context.Context, Verdict) error
}

// RateReport is the runtime reporting rule for one policy on this node (see
// enforcement.FailRate): Degraded on any fail-closed refusal (Strict) or
// unevaluated judgement (Audit) in the last 60 s; NotReady above 0.1 % of the
// attempts over 5 min; Unknown when a counter is unreadable or moved
// backwards, never a zero rate.
type RateReport struct {
	Unknown            error
	Degraded, NotReady bool
	Message            string
	// Suppressed counts the denies with no verdict event (the kernel's
	// per-CPU report limit, or a full ring buffer) in the last 60 s of the
	// sections that have the policy. The counters are per section for the
	// whole node, not per policy. Enforcement is unchanged; the status shows
	// it as Degraded (VerdictsSuppressed). SuppressedNote names each section
	// with its count.
	Suppressed     uint64
	SuppressedNote string
	// SuppressedUnknown names the sections whose lost verdicts cannot be
	// counted: a verdict counter is unreadable (for as long as it stays so),
	// or was unreadable or created again in the last 60 s. Never read as
	// zero loss.
	SuppressedUnknown string
}

// RateReporter samples the reporting counters (SampleRates, periodically)
// and applies the rule to a policy (PolicyRates; ok false when no section
// slot has it).
type RateReporter interface {
	SampleRates(now time.Time)
	PolicyRates(uid types.UID, now time.Time) (report RateReport, ok bool)
}
