//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignedConfigRejectsPurposeSwap(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct {
		raw            string
		purpose, other ConfigPurpose
	}{
		{nodeAgentConfigJSON, NodeAgentConfigPurpose, ClusterDataPurpose},
		{clusterDataJSON, ClusterDataPurpose, NodeAgentConfigPurpose},
	} {
		t.Run(string(tc.purpose), func(t *testing.T) {
			signed, fp := signConfigWithFingerprint(t, tc.raw, tc.purpose, key)
			got, err := verifyAndPinConfig(signed, fp, tc.purpose)
			require.NoError(t, err)
			require.JSONEq(t, tc.raw, string(got))
			_, err = verifyAndPinConfig(signed, fp, tc.other)
			require.ErrorContains(t, err, "does not match expected")
			// Neither the mounted filename nor the same root signer grants permission
			// to use a config intended for a different consumer.
			path := filepath.Join(t.TempDir(), "config.signed.json")
			require.NoError(t, os.WriteFile(path, signed, 0600))
			_, err = loadSignedConfigWithRoot(path, fp, tc.other)
			require.ErrorContains(t, err, "does not match expected")

			var artifact signedConfigArtifact
			require.NoError(t, json.Unmarshal(signed, &artifact))
			artifact.Purpose = tc.other
			retagged, err := json.Marshal(artifact)
			require.NoError(t, err)
			_, err = verifyAndPinConfig(retagged, fp, tc.other)
			require.ErrorContains(t, err, "signature verification failed")

			artifact.Purpose = ""
			legacy, err := json.Marshal(artifact)
			require.NoError(t, err)
			_, err = verifyAndPinConfig(legacy, fp, tc.purpose)
			require.ErrorContains(t, err, "does not match expected")
		})
	}
}

func TestSignedConfigRejectsMissingOrUnknownPurpose(t *testing.T) {
	for _, purpose := range []ConfigPurpose{"", "trust-policy"} {
		_, err := SignConfig([]byte(nodeAgentConfigJSON), purpose, genKey(t))
		require.ErrorContains(t, err, "invalid signed config purpose")
	}
}

func TestSignedConfigRejectsTrustPolicyArtifact(t *testing.T) {
	key := genKey(t)
	signed, err := SignTrustPolicy(&TrustPolicy{}, key)
	require.NoError(t, err)
	_, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, NodeAgentConfigPurpose, key)
	for _, purpose := range []ConfigPurpose{NodeAgentConfigPurpose, ClusterDataPurpose} {
		_, err := verifyAndPinConfig(signed, fp, purpose)
		require.Error(t, err)
	}
}
