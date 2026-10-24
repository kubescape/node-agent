//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func TestSigningPolicyReloadDisablesLearnedChecksumSkip(t *testing.T) {
	cp := learnedCPWithChecksum("learned", "1", "checksum")
	client := &checksumRecordingClient{learned: cp}
	c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
	entry := seedChecksumEntry(c, "id", cp, "checksum", "")
	c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeAlert})
	c.refreshOneEntry(context.Background(), "id", entry)
	require.Equal(t, []string{"checksum"}, client.checksumsFor(cp.Name))

	c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
	c.refreshOneEntry(context.Background(), "id", entry)
	require.Equal(t, []string{"checksum", ""}, client.checksumsFor(cp.Name))
	refused, ok := c.entries.Load("id")
	require.True(t, ok)
	require.NotEqual(t, entry.Projected, refused.Projected,
		"enforcement must remove the unsigned learned projection despite an unchanged checksum")
}

func TestSigningRefreshRefusesAndRecoversWithoutRogueArtifacts(t *testing.T) {
	raw := signedGroupedCP(t)
	client := &scriptedProfileClient{byName: map[string]*v1beta1.ContainerProfile{raw.Name: raw}}
	c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
	c.cfg.EnableSignatureVerification = true
	exp := &captureExporter{}
	c.SetTamperAlertExporter(exp)
	flat := resolveAuthoredContainerSection(raw, "app")
	entry := newEntry(flat, "app", "pod", raw.Namespace, "uid")
	entry.CPName = "learned"
	entry.UserCPRef = &namespacedName{Namespace: raw.Namespace, Name: raw.Name}
	entry.UserCPRV = ""
	c.entries.Set("id", entry)
	c.refreshOneEntry(context.Background(), "id", entry)
	verified, _ := c.entries.Load("id")
	require.Equal(t, "7", verified.UserCPRV)

	// Even without an RV change verification must precede the cache fast-skip.
	raw.Spec.Containers[0].Execs = append(raw.Spec.Containers[0].Execs, v1beta1.ExecCalls{Path: "/bin/evil"})
	c.refreshOneEntry(context.Background(), "id", verified)
	refused, _ := c.entries.Load("id")
	require.Empty(t, refused.UserCPRV)
	require.NotEqual(t, verified.Projected, refused.Projected)
	require.NotNil(t, refused.UserCPRef, "reconciliation must retain the recovery target")
	require.Len(t, exp.ruleAlerts(), 1)
	require.Equal(t, "R1016", exp.ruleAlerts()[0].GetRuleId())

	require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(raw)))
	raw.ResourceVersion = "8"
	c.refreshOneEntry(context.Background(), "id", refused)
	healed, _ := c.entries.Load("id")
	require.Equal(t, "8", healed.UserCPRV)
	for _, alert := range exp.ruleAlerts() {
		require.NotEqual(t, "R1017", alert.GetRuleId())
	}
}

func TestSigningEmbeddedContentDoesNotMutateStorageObject(t *testing.T) {
	cp := signedEmbeddedCP(t)
	cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/stored-edit"})
	c := &ContainerProfileCacheImpl{}
	admitted, refused, _ := c.admitSignedProfile(cp, "")
	require.False(t, refused)
	require.Len(t, admitted.Spec.Execs, 1)
	require.Len(t, cp.Spec.Execs, 2)
}

func TestSigningPolicyReloadRejectsUnsignedCacheOnBundleError(t *testing.T) {
	cp := authoredCP("authored", "/bin/unsigned", "1")
	client := &storage.StorageHttpClientMock{ContainerProfiles: []*v1beta1.ContainerProfile{cp}}
	c := newReconcilerCache(t, client, newControllableK8sCache(), nil)
	c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeAlert})
	entry := newEntry(cp, "app", "pod", cp.Namespace, "uid")
	entry.CPName = "learned"
	entry.UserCPRef = &namespacedName{Namespace: cp.Namespace, Name: cp.Name}
	c.entries.Set("id", entry)
	c.refreshOneEntry(context.Background(), "id", entry)
	admitted, _ := c.entries.Load("id")
	require.Equal(t, "1", admitted.UserCPRV)
	fragment := cp.DeepCopy()
	fragment.Name = "invalid-base"
	fragment.Labels = map[string]string{bundle.LabelBundle: cp.Name, bundle.LabelFragmentClass: "base"}
	client.ContainerProfiles = append(client.ContainerProfiles, fragment)
	c.SetBundleConfig(&bundle.TrustPolicy{Mode: bundle.ModeEnforce})
	_, err := c.assembleUserBundle(context.Background(), cp.Namespace, cp.Name, "")
	require.Error(t, err)
	c.refreshOneEntry(context.Background(), "id", admitted)
	refused, ok := c.entries.Load("id")
	require.True(t, ok)
	require.Empty(t, refused.UserCPRV)
	require.Equal(t, admitted.UserCPRef, refused.UserCPRef)
	require.NotEqual(t, admitted.Projected, refused.Projected)
}

func TestMalformedSignatureAnnotationsEmitTamperAlert(t *testing.T) {
	for _, annotation := range []string{signature.AnnotationSignature, signature.AnnotationCertificate, signature.AnnotationTimestamp} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enforce=%t", annotation, enforce), func(t *testing.T) {
				cp := authoredCP("authored", "/bin/signed", "1")
				require.NoError(t, signature.SignObjectDisableKeyless(profiles.NewContainerProfileAdapter(cp)))
				cp.Spec.Execs = []v1beta1.ExecCalls{{Path: "/bin/edited"}}
				cp.Annotations[annotation] = "!malformed!"
				c := &ContainerProfileCacheImpl{}
				mode := bundle.ModeAlert
				if enforce {
					mode = bundle.ModeEnforce
				}
				c.SetBundleConfig(&bundle.TrustPolicy{Mode: mode})
				exp := &captureExporter{}
				c.SetTamperAlertExporter(exp)
				_, refused, provenance := c.admitSignedProfile(cp, "wlid://cluster-a/namespace-default/deployment-test")
				require.Equal(t, enforce, refused)
				require.False(t, provenance.verifiedFlat)
				require.Len(t, exp.ruleAlerts(), 1, "malformed annotations on signed content must produce R1016 even in alert mode")
				require.Equal(t, "R1016", exp.ruleAlerts()[0].GetRuleId())
			})
		}
	}
}
