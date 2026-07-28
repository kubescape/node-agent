package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func baseCP() *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cp", Namespace: "default", ResourceVersion: "1"},
		Spec: v1beta1.ContainerProfileSpec{
			Capabilities: []string{"SYS_PTRACE"},
			Execs: []v1beta1.ExecCalls{
				{Path: "/bin/ls", Args: []string{"-la"}},
			},
			PolicyByRuleId: map[string]v1beta1.RulePolicy{
				"R0901": {AllowedProcesses: []string{"ls"}},
			},
			Ingress: []v1beta1.NetworkNeighbor{
				{Identifier: "ing-1", DNSNames: []string{"a.svc.local"}},
			},
		},
	}
}

// userManagedCPWith builds a "ug-" user-managed ContainerProfile overlay from a
// flat spec. This is the migrated replacement for the legacy per-container
// ApplicationProfile + NetworkNeighborhood overlay pair.
func userManagedCPWith(spec v1beta1.ContainerProfileSpec) *v1beta1.ContainerProfile {
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ug-nginx", Namespace: "default", ResourceVersion: "u1"},
		Spec:       spec,
	}
}

// TestProjection_UserCPOnly_Merge verifies the happy-path merge of a
// user-managed ContainerProfile overlay: capabilities / execs / policies
// unioned into the base.
func TestProjection_UserCPOnly_Merge(t *testing.T) {
	cp := baseCP()
	userCP := userManagedCPWith(v1beta1.ContainerProfileSpec{
		Capabilities: []string{"NET_BIND_SERVICE"},
		Execs:        []v1beta1.ExecCalls{{Path: "/bin/cat"}},
		PolicyByRuleId: map[string]v1beta1.RulePolicy{
			"R0901": {AllowedProcesses: []string{"cat"}},
			"R0902": {AllowedProcesses: []string{"echo"}},
		},
	})

	projected := projectUserManagedCP(cp, userCP)
	require.NotNil(t, projected)
	assert.NotSame(t, cp, projected, "projected must be a distinct DeepCopy")
	assert.ElementsMatch(t, []string{"SYS_PTRACE", "NET_BIND_SERVICE"}, projected.Spec.Capabilities)
	assert.Len(t, projected.Spec.Execs, 2)
	// R0901 merged, R0902 added
	assert.Contains(t, projected.Spec.PolicyByRuleId, "R0901")
	assert.Contains(t, projected.Spec.PolicyByRuleId, "R0902")
}

// TestProjection_UserCP_Network verifies merge of the network surface: ingress
// merged by Identifier (DNSNames unioned), LabelSelector MatchLabels overlaid.
func TestProjection_UserCP_Network(t *testing.T) {
	cp := baseCP()
	cp.Spec.LabelSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}
	userCP := userManagedCPWith(v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{
			{Identifier: "ing-1", DNSNames: []string{"b.svc.local"}},
			{Identifier: "ing-2", DNSNames: []string{"c.svc.local"}},
		},
	})
	userCP.Spec.LabelSelector = metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}

	projected := projectUserManagedCP(cp, userCP)
	require.NotNil(t, projected)
	require.Len(t, projected.Spec.Ingress, 2)
	// ing-1 merged (DNSNames union)
	var merged v1beta1.NetworkNeighbor
	for _, ing := range projected.Spec.Ingress {
		if ing.Identifier == "ing-1" {
			merged = ing
			break
		}
	}
	assert.ElementsMatch(t, []string{"a.svc.local", "b.svc.local"}, merged.DNSNames)
	// LabelSelector overlaid
	assert.Equal(t, "nginx", projected.Spec.LabelSelector.MatchLabels["app"])
	assert.Equal(t, "prod", projected.Spec.LabelSelector.MatchLabels["env"])
}

// TestProjection_UserCP_Both verifies capabilities and ingress overlay together
// in a single merge.
func TestProjection_UserCP_Both(t *testing.T) {
	cp := baseCP()
	userCP := userManagedCPWith(v1beta1.ContainerProfileSpec{
		Capabilities: []string{"NET_ADMIN"},
		Ingress:      []v1beta1.NetworkNeighbor{{Identifier: "ing-new"}},
	})

	projected := projectUserManagedCP(cp, userCP)
	require.NotNil(t, projected)
	assert.Contains(t, projected.Spec.Capabilities, "NET_ADMIN")
	// Original ing-1 plus appended ing-new
	assert.Len(t, projected.Spec.Ingress, 2)
}

// TestProjection_NilUserCP verifies projection with no overlay returns a
// DeepCopy (distinct pointer) preserving the base.
func TestProjection_NilUserCP(t *testing.T) {
	cp := baseCP()

	projected := projectUserManagedCP(cp, nil)
	require.NotNil(t, projected)
	assert.NotSame(t, cp, projected)
	assert.Equal(t, cp.Spec.Capabilities, projected.Spec.Capabilities)
}
