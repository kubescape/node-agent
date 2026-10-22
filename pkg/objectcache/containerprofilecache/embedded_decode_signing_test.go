//go:build experimental_signing

package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/stretchr/testify/require"
)

// Override only the signed payload so the signature is valid even though its
// embedded spec cannot be interpreted as a ContainerProfileSpec.
type invalidEmbeddedProfile struct {
	*profiles.ContainerProfileAdapter
	spec interface{}
}

func (p invalidEmbeddedProfile) GetContent() interface{} {
	return map[string]interface{}{
		"metadata": map[string]interface{}{"name": p.GetName()},
		"spec":     p.spec,
	}
}

func TestAdmissionRejectsInvalidVerifiedEmbeddedSpec(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		mode := "permissive"
		if enforce {
			mode = "enforcing"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				spec interface{}
			}{
				{"wrong-type", "not a profile spec"},
				{"wrong-field-type", map[string]interface{}{"execs": "not an array"}},
				{"null", nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cp := signedCP("invalid-embedded", "test", "1")
					original := cp.Spec.DeepCopy()
					adapter := profiles.NewContainerProfileAdapter(cp)
					require.NoError(t, signature.SignObject(invalidEmbeddedProfile{adapter, tc.spec}, signature.WithKeyless(false), signature.WithEmbedContent(true)))
					require.NoError(t, signature.VerifyObjectAllowUntrusted(adapter), "this is an embedded schema failure, not a cryptographic failure")
					cache := &ContainerProfileCacheImpl{}
					cache.cfg.EnableSignatureVerification = enforce
					exporter := &captureExporter{}
					cache.SetTamperAlertExporter(exporter)
					admitted, refused, _ := cache.admitSignedProfile(cp, "")
					require.True(t, refused, "invalid signed content must never fall back to the mutable stored spec")
					require.Nil(t, admitted)
					require.False(t, cache.verifyUserContainerProfile(cp.DeepCopy(), ""), "the boolean verification helper must refuse invalid embedded content too")
					require.Equal(t, original, &cp.Spec, "admission must preserve the storage client's object")
					require.Empty(t, exporter.ruleAlerts(), "a valid signature with an invalid schema is not tampering")
				})
			}
		})
	}
}
