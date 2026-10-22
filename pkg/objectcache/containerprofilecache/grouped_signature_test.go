//go:build experimental_signing

// Pins the A5-A8 verification object: the signature binds the RAW fetched
// grouped document; resolveAuthoredContainerSection rebuilds the spec, so
// verifying the flattened view always mismatches (observed live: clean
// tamper-app refused with a false R1016 within 1s of signing).
package containerprofilecache

import (
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func signedGroupedCP(t *testing.T) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tamper-app", Namespace: "prod", ResourceVersion: "7",
			Annotations: map[string]string{"kubescape.io/managed-by": "User"},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures: []string{"amd64"},
			Containers: []v1beta1.ContainerProfileContainer{{
				Name:  "app",
				Execs: []v1beta1.ExecCalls{{Path: "/bin/sleep", Args: []string{"/bin/sleep", "3600"}}},
			}},
		},
	}
	require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(cp)))
	return cp
}

func TestVerify_GroupedDoc_RawVerifiesFlattenedDoesNot(t *testing.T) {
	raw := signedGroupedCP(t)
	require.NoError(t, signature.VerifyObjectAllowUntrusted(profiles.NewContainerProfileAdapter(raw)),
		"the raw signed grouped doc must verify clean")

	flat := resolveAuthoredContainerSection(raw, "app")
	require.NotNil(t, flat)
	err := signature.VerifyObjectAllowUntrusted(profiles.NewContainerProfileAdapter(flat))
	require.Error(t, err, "flattening rebuilds the spec — the signed digest cannot match")
	require.True(t, errors.Is(err, signature.ErrSignatureMismatch),
		"the flattened-view failure is a digest mismatch, which is why verify MUST run on the raw doc")
}

func TestVerify_GroupedDoc_VerdictOKOnRaw_TamperStillCaught(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	raw := signedGroupedCP(t)
	require.Equal(t, verifyOK, c.verifyUserContainerProfileVerdict(raw, "wlid://c/ns-prod/deployment-d"),
		"a clean grouped doc must be verifyOK on the raw object — no false R1016 (A7)")

	raw.Spec.Containers[0].Execs = append(raw.Spec.Containers[0].Execs, v1beta1.ExecCalls{Path: "/bin/evil"})
	raw.ResourceVersion = "8"
	require.Equal(t, verifyTampered, c.verifyUserContainerProfileVerdict(raw, "wlid://c/ns-prod/deployment-d"),
		"a post-signing section edit must still classify as tamper (A7)")
}
