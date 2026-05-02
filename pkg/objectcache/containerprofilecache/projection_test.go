package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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

func podWith(containers ...string) *corev1.Pod {
	var cs []corev1.Container
	for _, n := range containers {
		cs = append(cs, corev1.Container{Name: n})
	}
	return &corev1.Pod{Spec: corev1.PodSpec{Containers: cs}}
}

// TestProjection_UserAPOnly_Match verifies the happy-path merge of a matching
// user AP container: capabilities / execs / policies merged, no warnings.
func TestProjection_UserAPOnly_Match(t *testing.T) {
	cp := baseCP()
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ua", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_BIND_SERVICE"},
				Execs:        []v1beta1.ExecCalls{{Path: "/bin/cat"}},
				PolicyByRuleId: map[string]v1beta1.RulePolicy{
					"R0901": {AllowedProcesses: []string{"cat"}},
					"R0902": {AllowedProcesses: []string{"echo"}},
				},
			}},
		},
	}
	pod := podWith("nginx")

	projected, warnings := projectUserProfiles(cp, userAP, nil, pod, "nginx")
	require.NotNil(t, projected)
	assert.Empty(t, warnings)
	assert.NotSame(t, cp, projected, "projected must be a distinct DeepCopy")
	assert.ElementsMatch(t, []string{"SYS_PTRACE", "NET_BIND_SERVICE"}, projected.Spec.Capabilities)
	assert.Len(t, projected.Spec.Execs, 2)
	// R0901 merged, R0902 added
	assert.Contains(t, projected.Spec.PolicyByRuleId, "R0901")
	assert.Contains(t, projected.Spec.PolicyByRuleId, "R0902")
}

// TestProjection_UserNNOnly_Match verifies merge of matching NN container:
// ingress merged by Identifier, LabelSelector MatchLabels overlaid.
func TestProjection_UserNNOnly_Match(t *testing.T) {
	cp := baseCP()
	cp.Spec.LabelSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}
	userNN := &v1beta1.NetworkNeighborhood{
		ObjectMeta: metav1.ObjectMeta{Name: "un", Namespace: "default", ResourceVersion: "n1"},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
			Containers: []v1beta1.NetworkNeighborhoodContainer{{
				Name: "nginx",
				Ingress: []v1beta1.NetworkNeighbor{
					{Identifier: "ing-1", DNSNames: []string{"b.svc.local"}},
					{Identifier: "ing-2", DNSNames: []string{"c.svc.local"}},
				},
			}},
		},
	}
	pod := podWith("nginx")

	projected, warnings := projectUserProfiles(cp, nil, userNN, pod, "nginx")
	require.NotNil(t, projected)
	assert.Empty(t, warnings)
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

// TestProjection_Both verifies both AP and NN can overlay in a single call.
func TestProjection_Both(t *testing.T) {
	cp := baseCP()
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ua", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_ADMIN"},
			}},
		},
	}
	userNN := &v1beta1.NetworkNeighborhood{
		ObjectMeta: metav1.ObjectMeta{Name: "un", Namespace: "default", ResourceVersion: "n1"},
		Spec: v1beta1.NetworkNeighborhoodSpec{
			Containers: []v1beta1.NetworkNeighborhoodContainer{{
				Name:    "nginx",
				Ingress: []v1beta1.NetworkNeighbor{{Identifier: "ing-new"}},
			}},
		},
	}
	pod := podWith("nginx")

	projected, warnings := projectUserProfiles(cp, userAP, userNN, pod, "nginx")
	require.NotNil(t, projected)
	assert.Empty(t, warnings)
	assert.Contains(t, projected.Spec.Capabilities, "NET_ADMIN")
	// Original ing-1 plus appended ing-new
	assert.Len(t, projected.Spec.Ingress, 2)
}

// TestProjection_UserAP_NonMatchingContainer verifies that when the user CRD
// doesn't include the target container name, no merge happens — but missing
// pod containers still produce a warning.
func TestProjection_UserAP_NonMatchingContainer(t *testing.T) {
	cp := baseCP()
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ua", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "other", // not "nginx"
				Capabilities: []string{"NET_BIND_SERVICE"},
			}},
		},
	}
	pod := podWith("nginx", "sidecar")

	projected, warnings := projectUserProfiles(cp, userAP, nil, pod, "nginx")
	require.NotNil(t, projected)
	// No merge because no container matched "nginx"
	assert.ElementsMatch(t, []string{"SYS_PTRACE"}, projected.Spec.Capabilities)
	require.Len(t, warnings, 1)
	assert.Equal(t, kindApplication, warnings[0].Kind)
	assert.ElementsMatch(t, []string{"nginx", "sidecar"}, warnings[0].MissingContainers)
}

// TestProjection_UserAP_PartialContainers verifies that when the user AP has
// one container but the pod has two, we emit a partial warning naming the
// missing pod container.
func TestProjection_UserAP_PartialContainers(t *testing.T) {
	cp := baseCP()
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ua", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_BIND_SERVICE"},
			}},
		},
	}
	pod := podWith("nginx", "sidecar")

	projected, warnings := projectUserProfiles(cp, userAP, nil, pod, "nginx")
	require.NotNil(t, projected)
	// Target container merged.
	assert.Contains(t, projected.Spec.Capabilities, "NET_BIND_SERVICE")
	require.Len(t, warnings, 1)
	assert.Equal(t, kindApplication, warnings[0].Kind)
	assert.Equal(t, []string{"sidecar"}, warnings[0].MissingContainers)
}

// TestProjection_NoUserCRDs verifies projection with neither user CRD returns
// a DeepCopy (distinct pointer) and no warnings.
func TestProjection_NoUserCRDs(t *testing.T) {
	cp := baseCP()
	pod := podWith("nginx")

	projected, warnings := projectUserProfiles(cp, nil, nil, pod, "nginx")
	require.NotNil(t, projected)
	assert.Empty(t, warnings)
	assert.NotSame(t, cp, projected)
	assert.Equal(t, cp.Spec.Capabilities, projected.Spec.Capabilities)
}

// TestProjection_NilPod verifies the merge still runs when pod is nil; the
// missing-container check is skipped (no warning emitted for partial).
func TestProjection_NilPod(t *testing.T) {
	cp := baseCP()
	userAP := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "ua", Namespace: "default", ResourceVersion: "u1"},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{{
				Name:         "nginx",
				Capabilities: []string{"NET_BIND_SERVICE"},
			}},
		},
	}

	projected, warnings := projectUserProfiles(cp, userAP, nil, nil, "nginx")
	require.NotNil(t, projected)
	assert.Empty(t, warnings)
	assert.Contains(t, projected.Spec.Capabilities, "NET_BIND_SERVICE")
}
