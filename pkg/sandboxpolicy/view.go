package sandboxpolicy

import (
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyView exposes one parsed policy to enforcement layers other than exec.
// It applies the same selector rules as the exec controller.
type PolicyView struct {
	Identity PolicyIdentity
	Spec     api.PolicySpec
	// Err is a parse or validation error. An invalid policy matches nothing.
	Err    error
	parsed desiredPolicy
}

// ParsePolicy parses a SandboxPolicy or ClusterSandboxPolicy object.
func ParsePolicy(u *unstructured.Unstructured) PolicyView {
	p := parsePolicy(u)
	return PolicyView{Identity: p.identity, Spec: p.spec, Err: p.err, parsed: p}
}

// Matches reports whether a valid, active policy selects the container.
func (v PolicyView) Matches(b Binding) bool {
	return v.Err == nil && v.Spec.Mode != api.ModeOff && v.parsed.matches(b)
}

// StatusContributor adds another layer's per-node state to a policy's report:
// rule names waiting for a container restart, and conditions that explain them.
// Any of either means the policy is not fully enforced on this node, so Ready
// turns False. Contribute must not block: it is called while the report is built.
type StatusContributor interface {
	Contribute(policy types.UID) (appliesOnRestart []string, conditions []metav1.Condition)
}

// ConditionPrivilegeNotEnforced marks privilege rules that no layer enforces on
// this node, because the seccomp layer is disabled.
const ConditionPrivilegeNotEnforced = "PrivilegeNotEnforced"

type seccompDisabled struct{}

func (seccompDisabled) Contribute(types.UID) ([]string, []metav1.Condition) {
	return nil, []metav1.Condition{{Type: ConditionPrivilegeNotEnforced, Status: metav1.ConditionTrue, Reason: "SeccompLayerDisabled", Message: "privilege rules need the seccomp layer (sandboxSeccompEnabled)"}}
}

func contribute(status *api.NodeStatus, policy types.UID, generation int64, now metav1.Time, contributors []StatusContributor) {
	added := 0
	for _, c := range contributors {
		pending, conditions := c.Contribute(policy)
		status.AppliesOnRestart = append(status.AppliesOnRestart, pending...)
		added += len(pending) + len(conditions)
		for _, condition := range conditions {
			if len(status.Conditions) >= api.MaxStatusConditions {
				status.Truncated = true
				break
			}
			condition.ObservedGeneration, condition.LastTransitionTime = generation, now
			status.Conditions = append(status.Conditions, condition)
		}
	}
	if added > 0 {
		for i := range status.Conditions {
			if status.Conditions[i].Type != "Ready" || status.Conditions[i].Status != metav1.ConditionTrue {
				continue
			}
			status.Conditions[i].Status, status.Conditions[i].Reason = metav1.ConditionFalse, "NotFullyEnforced"
			if len(status.AppliesOnRestart) > 0 {
				status.Conditions[i].Reason = "AppliesOnRestart"
			}
			status.Conditions[i].Message = "some rules are not enforced on this node; see the other conditions"
		}
	}
	// Counts keep the full cardinality; the detail list is bounded.
	status.Counts.AppliesOnRestart = int64(len(status.AppliesOnRestart))
	if len(status.AppliesOnRestart) > api.MaxStatusRuleDetails {
		status.AppliesOnRestart, status.Truncated = status.AppliesOnRestart[:api.MaxStatusRuleDetails], true
	}
}

// ContributeStatus applies contributors to a report built outside the controller.
func ContributeStatus(status *api.NodeStatus, policy types.UID, generation int64, now metav1.Time, contributors ...StatusContributor) {
	contribute(status, policy, generation, now, contributors)
}
