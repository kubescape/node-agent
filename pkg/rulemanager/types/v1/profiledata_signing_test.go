//go:build experimental_signing

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestProfileDataRequired_Unmarshal_ExplicitNullJSON verifies that an EXPLICIT
// JSON null from previously serialized signing payloads unmarshals
// back to a nil surface instead of being rejected. Without this, any Rules
// object that has been re-serialised through this type — the offline signing
// CLI, the signed-content blob embedded in a signed Rules fragment, an
// apiserver round-trip — fails to parse and the whole fragment is dropped.
func TestProfileDataRequired_Unmarshal_ExplicitNullJSON(t *testing.T) {
	data := `{"execs":"all","capabilities":null,"opens":null}`
	var pdr ProfileDataRequired
	require.NoError(t, json.Unmarshal([]byte(data), &pdr))

	require.NotNil(t, pdr.Execs)
	assert.True(t, pdr.Execs.All)
	assert.Nil(t, pdr.Capabilities, "explicit null must mean undeclared")
	assert.Nil(t, pdr.Opens, "explicit null must mean undeclared")
}

// TestProfileDataRequired_Unmarshal_ExplicitNullYAML is the YAML twin of
// TestProfileDataRequired_Unmarshal_ExplicitNullJSON.
func TestProfileDataRequired_Unmarshal_ExplicitNullYAML(t *testing.T) {
	input := "execs: all\ncapabilities: null\nopens: ~\n"
	var pdr ProfileDataRequired
	require.NoError(t, yaml.Unmarshal([]byte(input), &pdr))

	require.NotNil(t, pdr.Execs)
	assert.True(t, pdr.Execs.All)
	assert.Nil(t, pdr.Capabilities, "explicit null must mean undeclared")
	assert.Nil(t, pdr.Opens, "explicit ~ must mean undeclared")
}

// TestProfileDataRequired_MarshalUnmarshal_RoundTrip pins the symmetry the two
// tests above rely on: marshal → unmarshal must preserve every declaration.
func TestProfileDataRequired_MarshalUnmarshal_RoundTrip(t *testing.T) {
	original := ProfileDataRequired{
		Execs: &FieldRequirement{All: true},
		Opens: &FieldRequirement{Patterns: []PatternObject{{Prefix: "/etc/"}}},
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)

	var round ProfileDataRequired
	require.NoError(t, json.Unmarshal(data, &round), "marshalled form must be re-parseable: %s", data)
	assert.Equal(t, original, round)
}

// TestProfileDataRequired_Unmarshal_EmptyStringStillRejected verifies the null
// acceptance did not open the door to an empty string, which stays invalid.
func TestProfileDataRequired_Unmarshal_EmptyStringStillRejected(t *testing.T) {
	var pdr ProfileDataRequired
	assert.Error(t, json.Unmarshal([]byte(`{"execs":""}`), &pdr))
}
