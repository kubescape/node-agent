package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// --- YAML unmarshaling tests ---

// TestProfileDataRequired_Unmarshal_AllString verifies that the string "all"
// unmarshals to FieldRequirement{Declared:true, All:true}.
func TestProfileDataRequired_Unmarshal_AllString(t *testing.T) {
	input := `opens: all`
	var pdr ProfileDataRequired
	err := yaml.Unmarshal([]byte(input), &pdr)
	require.NoError(t, err)

	assert.True(t, pdr.Opens.Declared, "Declared should be true when field is present in YAML")
	assert.True(t, pdr.Opens.All, "All should be true when value is 'all'")
	assert.Empty(t, pdr.Opens.Patterns, "Patterns should be empty when value is 'all'")
}

// TestProfileDataRequired_Unmarshal_Patterns verifies that a list of pattern
// objects unmarshals correctly.
func TestProfileDataRequired_Unmarshal_Patterns(t *testing.T) {
	input := `
opens:
  - exact: /bin/sh
  - prefix: /usr/
`
	var pdr ProfileDataRequired
	err := yaml.Unmarshal([]byte(input), &pdr)
	require.NoError(t, err)

	assert.True(t, pdr.Opens.Declared)
	assert.False(t, pdr.Opens.All)
	require.Len(t, pdr.Opens.Patterns, 2, "should have two pattern entries")

	// Find exact and prefix entries (order may vary).
	var exactFound, prefixFound bool
	for _, p := range pdr.Opens.Patterns {
		if p.Exact == "/bin/sh" {
			exactFound = true
		}
		if p.Prefix == "/usr/" {
			prefixFound = true
		}
	}
	assert.True(t, exactFound, "exact /bin/sh pattern should be present")
	assert.True(t, prefixFound, "prefix /usr/ pattern should be present")
}

// TestProfileDataRequired_Unmarshal_NilField verifies that an omitted field
// results in Declared=false.
func TestProfileDataRequired_Unmarshal_NilField(t *testing.T) {
	// Only opens is specified; syscalls is omitted.
	input := `opens: all`
	var pdr ProfileDataRequired
	err := yaml.Unmarshal([]byte(input), &pdr)
	require.NoError(t, err)

	assert.False(t, pdr.Syscalls.Declared, "omitted syscalls field should have Declared=false")
	assert.False(t, pdr.Execs.Declared, "omitted execs field should have Declared=false")
}

// TestProfileDataRequired_Unmarshal_InvalidPattern verifies that a pattern
// object with two fields is rejected at unmarshal time.
func TestProfileDataRequired_Unmarshal_InvalidPattern(t *testing.T) {
	input := `
opens:
  - exact: /a
    prefix: /b
`
	var pdr ProfileDataRequired
	err := yaml.Unmarshal([]byte(input), &pdr)
	assert.Error(t, err, "a PatternObject with two fields (exact+prefix) should return an error")
}

// TestProfileDataRequired_Unmarshal_ValidateSingleField verifies that each
// single-field PatternObject variant is accepted.
func TestProfileDataRequired_Unmarshal_ValidateSingleField(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "exact", input: "opens:\n  - exact: /bin/sh"},
		{name: "prefix", input: "opens:\n  - prefix: /usr/"},
		{name: "suffix", input: "opens:\n  - suffix: .log"},
		{name: "contains", input: "opens:\n  - contains: http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pdr ProfileDataRequired
			err := yaml.Unmarshal([]byte(tc.input), &pdr)
			require.NoError(t, err, "single-field pattern %q should be valid", tc.name)
			assert.True(t, pdr.Opens.Declared)
			require.Len(t, pdr.Opens.Patterns, 1)
		})
	}
}

// TestProfileDataRequired_Unmarshal_TwoFieldsInOneObject verifies that a pattern
// object with more than one non-empty field is rejected.
func TestProfileDataRequired_Unmarshal_TwoFieldsInOneObject(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "exact+prefix",
			input: "opens:\n  - exact: /a\n    prefix: /b",
		},
		{
			name:  "suffix+contains",
			input: "opens:\n  - suffix: .log\n    contains: http",
		},
		{
			name:  "exact+suffix",
			input: "opens:\n  - exact: /bin/sh\n    suffix: .sh",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pdr ProfileDataRequired
			err := yaml.Unmarshal([]byte(tc.input), &pdr)
			assert.Error(t, err, "multi-field PatternObject %q should be rejected", tc.name)
		})
	}
}

// TestProfileDataRequired_Unmarshal_AllFields verifies that all field names in
// ProfileDataRequired can be round-tripped from YAML.
func TestProfileDataRequired_Unmarshal_AllFields(t *testing.T) {
	input := `
opens: all
execs:
  - prefix: /usr/
capabilities: all
syscalls:
  - contains: read
endpoints: all
egressDomains:
  - exact: example.com
egressAddresses:
  - prefix: 10.0.
ingressDomains: all
ingressAddresses:
  - suffix: .local
`
	var pdr ProfileDataRequired
	err := yaml.Unmarshal([]byte(input), &pdr)
	require.NoError(t, err)

	assert.True(t, pdr.Opens.All)
	assert.True(t, pdr.Execs.Declared)
	assert.False(t, pdr.Execs.All)
	require.Len(t, pdr.Execs.Patterns, 1)
	assert.Equal(t, "/usr/", pdr.Execs.Patterns[0].Prefix)

	assert.True(t, pdr.Capabilities.All)
	assert.True(t, pdr.Syscalls.Declared)
	require.Len(t, pdr.Syscalls.Patterns, 1)
	assert.Equal(t, "read", pdr.Syscalls.Patterns[0].Contains)

	assert.True(t, pdr.Endpoints.All)
	assert.True(t, pdr.EgressDomains.Declared)
	assert.Equal(t, "example.com", pdr.EgressDomains.Patterns[0].Exact)
	assert.Equal(t, "10.0.", pdr.EgressAddresses.Patterns[0].Prefix)
	assert.True(t, pdr.IngressDomains.All)
	assert.Equal(t, ".local", pdr.IngressAddresses.Patterns[0].Suffix)
}

// --- JSON unmarshaling tests ---

// TestFieldRequirement_JSON_AllString verifies JSON "all" string unmarshaling.
func TestFieldRequirement_JSON_AllString(t *testing.T) {
	data := `{"opens": "all"}`
	var pdr ProfileDataRequired
	err := json.Unmarshal([]byte(data), &pdr)
	require.NoError(t, err)

	assert.True(t, pdr.Opens.Declared)
	assert.True(t, pdr.Opens.All)
}

// TestFieldRequirement_JSON_Patterns verifies JSON pattern list unmarshaling.
func TestFieldRequirement_JSON_Patterns(t *testing.T) {
	data := `{"opens": [{"exact": "/bin/sh"}, {"prefix": "/usr/"}]}`
	var pdr ProfileDataRequired
	err := json.Unmarshal([]byte(data), &pdr)
	require.NoError(t, err)

	assert.True(t, pdr.Opens.Declared)
	assert.False(t, pdr.Opens.All)
	require.Len(t, pdr.Opens.Patterns, 2)
}

// TestFieldRequirement_JSON_InvalidString verifies that a non-"all" string
// value is rejected.
func TestFieldRequirement_JSON_InvalidString(t *testing.T) {
	data := `{"opens": "some"}`
	var pdr ProfileDataRequired
	err := json.Unmarshal([]byte(data), &pdr)
	assert.Error(t, err, `string value other than "all" should be rejected`)
}

// TestFieldRequirement_JSON_TwoFieldPattern verifies that a multi-field pattern
// object is rejected during JSON unmarshaling.
func TestFieldRequirement_JSON_TwoFieldPattern(t *testing.T) {
	data := `{"opens": [{"exact": "/a", "prefix": "/b"}]}`
	var pdr ProfileDataRequired
	err := json.Unmarshal([]byte(data), &pdr)
	assert.Error(t, err, "multi-field PatternObject should be rejected in JSON")
}

// TestFieldRequirement_MarshalJSON_All verifies that MarshalJSON for All=true
// emits the string "all".
func TestFieldRequirement_MarshalJSON_All(t *testing.T) {
	f := FieldRequirement{Declared: true, All: true}
	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.Equal(t, `"all"`, string(data))
}

// TestFieldRequirement_MarshalJSON_NotDeclared verifies that MarshalJSON for
// Declared=false emits null.
func TestFieldRequirement_MarshalJSON_NotDeclared(t *testing.T) {
	f := FieldRequirement{Declared: false}
	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.Equal(t, `null`, string(data))
}

// TestFieldRequirement_MarshalJSON_Patterns verifies that MarshalJSON for
// pattern lists emits the correct JSON array.
func TestFieldRequirement_MarshalJSON_Patterns(t *testing.T) {
	f := FieldRequirement{
		Declared: true,
		Patterns: []PatternObject{
			{Exact: "/bin/sh"},
			{Prefix: "/usr/"},
		},
	}
	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"exact":"/bin/sh"`)
	assert.Contains(t, string(data), `"prefix":"/usr/"`)
}

// TestPatternObject_Validate_EmptyObject verifies that a PatternObject with no
// fields is rejected.
func TestPatternObject_Validate_EmptyObject(t *testing.T) {
	// Use JSON unmarshaling path to trigger validate.
	data := `{"opens": [{}]}`
	var pdr ProfileDataRequired
	err := json.Unmarshal([]byte(data), &pdr)
	assert.Error(t, err, "empty PatternObject should be rejected")
}
