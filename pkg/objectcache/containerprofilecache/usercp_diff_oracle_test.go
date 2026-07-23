package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	dynamicpathdetector "github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The differential oracle for the user-defined AP/NN -> ContainerProfile
// migration. It pins the migration contract at the ENFORCEMENT artifact level:
//
//	OLD path (what node-agent does today for a user-defined container):
//	    overlay the user AP + user NN onto the synthetic empty base CP, then Apply.
//	NEW path (after the migration):
//	    the user authors ONE ContainerProfile (produced by the converter); node-agent
//	    uses it as the base with no overlay, then Apply.
//
// If these two ProjectedContainerProfiles are equal for every representative
// user-defined shape, the migration is behaviour-preserving. Apply is a pure
// function of cp.Spec (+ the SyncChecksum annotation), so equality here is exactly
// enforcement-equivalence.

func udMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: "demo",
		Annotations: map[string]string{
			"kubescape.io/managed-by": "User",
			"kubescape.io/status":     "completed",
			"kubescape.io/completion": "complete",
		},
		Labels: map[string]string{
			"kubescape.io/workload-kind": "Deployment",
			"kubescape.io/workload-name": name,
		},
	}
}

// oracleCases mirror the real user-defined component tests (27/28/32/33):
// opens with wildcard/ellipsis anchoring, execs with argv wildcards, HTTP
// endpoints, and egress/ingress with a LabelSelector.
func oracleCases() []struct {
	name          string
	containerName string
	ap            *v1beta1.ApplicationProfile
	nn            *v1beta1.NetworkNeighborhood
} {
	dyn := dynamicpathdetector.DynamicIdentifier
	full := func() (*v1beta1.ApplicationProfile, *v1beta1.NetworkNeighborhood) {
		ap := &v1beta1.ApplicationProfile{
			ObjectMeta: udMeta("curl-overlay"),
			Spec: v1beta1.ApplicationProfileSpec{
				Architectures: []string{"amd64"},
				Containers: []v1beta1.ApplicationProfileContainer{{
					Name:         "curl",
					Capabilities: []string{"NET_BIND_SERVICE", "SYS_PTRACE"},
					Execs: []v1beta1.ExecCalls{
						{Path: "/usr/bin/curl", Args: []string{"curl", dyn}},
						{Path: "/bin/sh", Args: []string{"sh", "-c", "echo *"}},
					},
					Opens: []v1beta1.OpenCalls{
						{Path: "/etc/ssl/" + dyn, Flags: []string{"O_RDONLY"}},
						{Path: "/etc/ld.so.cache", Flags: []string{"O_RDONLY"}},
						{Path: "/var/log/*", Flags: []string{"O_RDONLY"}},
					},
					Syscalls: []string{"openat", "read", "connect"},
					Endpoints: []v1beta1.HTTPEndpoint{
						{Endpoint: ":8080/api/products", Methods: []string{"GET"}},
					},
					PolicyByRuleId: map[string]v1beta1.RulePolicy{
						"R0040": {AllowedProcesses: []string{"curl"}},
					},
				}},
			},
		}
		nn := &v1beta1.NetworkNeighborhood{
			ObjectMeta: udMeta("curl-overlay"),
			Spec: v1beta1.NetworkNeighborhoodSpec{
				LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "curl"}},
				Containers: []v1beta1.NetworkNeighborhoodContainer{{
					Name: "curl",
					Egress: []v1beta1.NetworkNeighbor{
						{Identifier: "eg-dns", DNS: "fusioncore.ai.", Type: "external",
							Ports: []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: p80()}}},
						{Identifier: "eg-ip", IPAddress: "162.0.217.171", Type: "external",
							Ports: []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: p80()}}},
					},
					Ingress: []v1beta1.NetworkNeighbor{
						{Identifier: "in-1", DNSNames: []string{"a.svc.local"}},
					},
				}},
			},
		}
		return ap, nn
	}
	apFull, nnFull := full()
	apOnly, _ := full()
	_, nnOnly := full()

	return []struct {
		name          string
		containerName string
		ap            *v1beta1.ApplicationProfile
		nn            *v1beta1.NetworkNeighborhood
	}{
		{"full_ap_and_nn", "curl", apFull, nnFull},
		{"ap_only", "curl", apOnly, nil},
		{"nn_only", "curl", nil, nnOnly},
		{"no_matching_container", "sidecar", apFull, nnFull},
	}
}

func p80() *int32 { v := int32(80); return &v }

func TestDiffOracle_UserDefinedCP_MatchesLegacyOverlay(t *testing.T) {
	for _, tc := range oracleCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pod := podWith("curl")

			// OLD path: overlay user AP + NN onto the synthetic empty base.
			emptyBase := &v1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "demo"},
			}
			legacyCP, _ := projectUserProfiles(emptyBase, tc.ap, tc.nn, pod, tc.containerName)

			// NEW path: the converted single ContainerProfile is the base, no overlay.
			userCP := ConvertUserProfilesToContainerProfile(tc.ap, tc.nn, pod, tc.containerName)
			newCP, _ := projectUserProfiles(userCP, nil, nil, pod, tc.containerName)

			// nil spec => full pass-through; equality here is spec-independent
			// (equal Specs => equal Apply for ANY RuleProjectionSpec).
			pLegacy := Apply(nil, legacyCP, nil)
			pNew := Apply(nil, newCP, nil)

			assert.Equal(t, pLegacy, pNew,
				"migrated user-defined ContainerProfile must enforce identically to the legacy AP+NN overlay")
		})
	}
}
