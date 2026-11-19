package types

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestRuleMitreMappings(t *testing.T) {
	for _, unmarshal := range []func([]byte, any) error{json.Unmarshal, yaml.Unmarshal} {
		var r Rule
		require.NoError(t, unmarshal([]byte(`{"mitreTactic":"TA0008","mitreTechnique":"T1021","mitreMappings":[{"tactic":"TA0008","technique":"T1021"},{"tactic":"TA0007","technique":"T1613"}]}`), &r))
		require.Len(t, r.GetMitreMappings(), 2)
		require.Equal(t, "T1613", r.GetMitreMappings()[1].Technique)
		data, err := json.Marshal(r)
		require.NoError(t, err)
		var roundtrip Rule
		require.NoError(t, json.Unmarshal(data, &roundtrip))
		require.Equal(t, r, roundtrip)
	}
	require.Len(t, (Rule{MitreTactic: "TA0008", MitreTechnique: "T1021"}).GetMitreMappings(), 1)
}
