package types

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ProfileDataRequired declares the per-rule profile fields the rule queries.
// Nil means the rule reads no profile data.
type ProfileDataRequired struct {
	Opens            FieldRequirement `json:"opens,omitempty"            yaml:"opens,omitempty"`
	Execs            FieldRequirement `json:"execs,omitempty"            yaml:"execs,omitempty"`
	Capabilities     FieldRequirement `json:"capabilities,omitempty"     yaml:"capabilities,omitempty"`
	Syscalls         FieldRequirement `json:"syscalls,omitempty"         yaml:"syscalls,omitempty"`
	Endpoints        FieldRequirement `json:"endpoints,omitempty"        yaml:"endpoints,omitempty"`
	EgressDomains    FieldRequirement `json:"egressDomains,omitempty"    yaml:"egressDomains,omitempty"`
	EgressAddresses  FieldRequirement `json:"egressAddresses,omitempty"  yaml:"egressAddresses,omitempty"`
	IngressDomains   FieldRequirement `json:"ingressDomains,omitempty"   yaml:"ingressDomains,omitempty"`
	IngressAddresses FieldRequirement `json:"ingressAddresses,omitempty" yaml:"ingressAddresses,omitempty"`
}

var profileDataRequiredKnownFields = map[string]bool{
	"opens": true, "execs": true, "capabilities": true,
	"syscalls": true, "endpoints": true,
	"egressDomains": true, "egressAddresses": true,
	"ingressDomains": true, "ingressAddresses": true,
}

// UnmarshalJSON rejects unknown fields.
func (p *ProfileDataRequired) UnmarshalJSON(data []byte) error {
	*p = ProfileDataRequired{} // reset to avoid stale state if receiver is reused
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k := range raw {
		if !profileDataRequiredKnownFields[k] {
			return fmt.Errorf("profileDataRequired: unknown field %q", k)
		}
	}
	type plain ProfileDataRequired
	return json.Unmarshal(data, (*plain)(p))
}

// UnmarshalYAML rejects unknown fields.
func (p *ProfileDataRequired) UnmarshalYAML(value *yaml.Node) error {
	*p = ProfileDataRequired{} // reset to avoid stale state if receiver is reused
	if value.Kind == yaml.MappingNode {
		for i := 0; i < len(value.Content)-1; i += 2 {
			key := value.Content[i].Value
			if !profileDataRequiredKnownFields[key] {
				return fmt.Errorf("profileDataRequired: unknown field %q", key)
			}
		}
	}
	type plain ProfileDataRequired
	return value.Decode((*plain)(p))
}

// FieldRequirement is the per-field declaration. After unmarshalling, exactly
// one of (All, Patterns) is meaningful. Declared=true when the YAML key was
// present, letting the spec compiler distinguish absent-from-this-rule vs
// explicitly declared.
type FieldRequirement struct {
	All      bool
	Patterns []PatternObject
	Declared bool
}

// PatternObject — exactly one of {Exact, Prefix, Suffix, Contains} is non-empty.
// Multi-key or empty objects are rejected at unmarshal time.
type PatternObject struct {
	Exact    string `json:"exact,omitempty"    yaml:"exact,omitempty"`
	Prefix   string `json:"prefix,omitempty"   yaml:"prefix,omitempty"`
	Suffix   string `json:"suffix,omitempty"   yaml:"suffix,omitempty"`
	Contains string `json:"contains,omitempty" yaml:"contains,omitempty"`
}

// validate checks that exactly one field is set.
func (p PatternObject) validate() error {
	count := 0
	if p.Exact != "" {
		count++
	}
	if p.Prefix != "" {
		count++
	}
	if p.Suffix != "" {
		count++
	}
	if p.Contains != "" {
		count++
	}
	if count == 0 {
		return fmt.Errorf("PatternObject must have exactly one non-empty field (exact/prefix/suffix/contains), got none")
	}
	if count > 1 {
		return fmt.Errorf("PatternObject must have exactly one non-empty field (exact/prefix/suffix/contains), got %d", count)
	}
	return nil
}

// UnmarshalJSON for FieldRequirement: accepts the string "all" or a non-empty
// JSON array of PatternObject.
func (f *FieldRequirement) UnmarshalJSON(data []byte) error {
	*f = FieldRequirement{} // reset to clear any stale All/Patterns before decode
	f.Declared = true

	// Try string "all"
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "all" {
			return fmt.Errorf("FieldRequirement string value must be \"all\", got %q", s)
		}
		f.All = true
		return nil
	}

	// Try array of PatternObject
	var patterns []PatternObject
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("FieldRequirement must be \"all\" or a list of pattern objects: %w", err)
	}
	if len(patterns) == 0 {
		return fmt.Errorf("FieldRequirement pattern list must be non-empty; use \"all\" to retain all entries")
	}
	for i, p := range patterns {
		if err := p.validate(); err != nil {
			return fmt.Errorf("FieldRequirement[%d]: %w", i, err)
		}
	}
	f.Patterns = patterns
	return nil
}

// MarshalJSON for FieldRequirement: emits "all" or the pattern list.
func (f FieldRequirement) MarshalJSON() ([]byte, error) {
	if !f.Declared {
		return []byte("null"), nil
	}
	if f.All {
		return []byte(`"all"`), nil
	}
	return json.Marshal(f.Patterns)
}

// UnmarshalYAML for FieldRequirement: accepts the string "all" or a non-empty
// sequence of pattern objects.
func (f *FieldRequirement) UnmarshalYAML(unmarshal func(any) error) error {
	*f = FieldRequirement{} // reset to clear any stale All/Patterns before decode
	f.Declared = true

	// Try string first.
	var s string
	if err := unmarshal(&s); err == nil {
		if s != "all" {
			return fmt.Errorf("FieldRequirement string value must be \"all\", got %q", s)
		}
		f.All = true
		return nil
	}

	// Try slice of PatternObject.
	var patterns []PatternObject
	if err := unmarshal(&patterns); err != nil {
		return fmt.Errorf("FieldRequirement must be \"all\" or a list of pattern objects: %w", err)
	}
	if len(patterns) == 0 {
		return fmt.Errorf("FieldRequirement pattern list must be non-empty; use \"all\" to retain all entries")
	}
	for i, p := range patterns {
		if err := p.validate(); err != nil {
			return fmt.Errorf("FieldRequirement[%d]: %w", i, err)
		}
	}
	f.Patterns = patterns
	return nil
}
