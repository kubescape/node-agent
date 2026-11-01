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
// Contribute must not block: it is called while the report is built.
type StatusContributor interface {
	Contribute(policy types.UID) (appliesOnRestart []string, conditions []metav1.Condition)
}

func contribute(status *api.NodeStatus, policy types.UID, generation int64, now metav1.Time, contributors []StatusContributor) {
	for _, c := range contributors {
		pending, conditions := c.Contribute(policy)
		status.AppliesOnRestart = append(status.AppliesOnRestart, pending...)
		for _, condition := range conditions {
			if len(status.Conditions) >= api.MaxStatusConditions {
				status.Truncated = true
				break
			}
			condition.ObservedGeneration, condition.LastTransitionTime = generation, now
			status.Conditions = append(status.Conditions, condition)
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
