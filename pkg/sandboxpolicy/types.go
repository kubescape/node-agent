// Package sandboxpolicy selects and compiles Kubernetes sandbox policies. It does
// not attach programs: Backend owns kernel capability validation and lifecycle.
package sandboxpolicy

import (
	"context"
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
	Origin   string
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
	Origin         string
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
}

type VerdictReceiver interface {
	ReportVerdict(context.Context, Verdict) error
}
