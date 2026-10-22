//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestBundle37FragmentsGrantExecPairs(t *testing.T) {
	root := "../../../tests/resources/signed/"
	var frags []*v1beta1.ContainerProfile
	for _, f := range []string{"fragments/bundle37-base-signed.yaml", "fragments/bundle37-admission-signed.yaml", "fragments/bundle37-overlay-signed.yaml"} {
		b, err := os.ReadFile(root + f)
		require.NoError(t, err)
		var cp v1beta1.ContainerProfile
		require.NoError(t, yaml.Unmarshal(b, &cp))
		frags = append(frags, &cp)
	}
	pb, err := os.ReadFile(root + "trust-policy.profiles-only.signed.json")
	require.NoError(t, err)
	var wrapped struct {
		Policy TrustPolicy `json:"policy"`
	}
	require.NoError(t, json.Unmarshal(pb, &wrapped))

	composite, manifest, dropped, err := AssembleAndVerifyPartial("bundle37", "", frags, wrapped.Policy)
	require.NoError(t, err)
	require.NotNil(t, composite)
	require.Empty(t, dropped, "every committed fragment must verify")
	require.NotNil(t, manifest)

	granted := map[string][]string{}
	for _, e := range composite.Spec.Execs {
		granted[e.Path] = append(granted[e.Path], e.Args...)
	}
	assert.Contains(t, granted, "/bin/busybox", "the multi-call binary is granted")
	assert.Contains(t, granted["/bin/busybox"], "/usr/bin/id", "granted under the overlay's name")
	assert.Contains(t, granted["/bin/busybox"], "/bin/sleep", "and the base's own command")
	assert.NotContains(t, granted["/bin/busybox"], "/bin/ls", "the sentinel applet is granted by no fragment")
}
