package types

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
)

// The profileDataRequired schema (the type, its match patterns, and the custom
// JSON/YAML/BSON (un)marshalling) lives in armoapi-go/armotypes — the single
// module imported by every consumer: node-agent (this query side: projection /
// was_path_opened), storage (the generation side: rule-aware collapse), and the
// backend (rules persisted in MongoDB). Defining it once there guarantees the
// matcher can never drift between the side that records a profile and the side
// that queries it.
//
// These aliases preserve node-agent's historical type names. Note the shape
// change versus the old node-agent-local schema: a surface is now a *pointer*
// (ProfileDataRequired.Opens is *ProfileDataField); a nil pointer means "this
// rule does not declare this surface" — the role the old `Declared` bool played.
type (
	ProfileDataRequired = armotypes.ProfileDataRequired
	FieldRequirement    = armotypes.ProfileDataField
	PatternObject       = armotypes.ProfileDataPattern
)

var (
	// KnownProfileDataSurfaces and KnownProfileDataPatternFields are extracted
	// dynamically from the canonical armotypes structs so node-agent never
	// duplicates the field lists and automatically inherits any new surfaces.
	KnownProfileDataSurfaces      = extractJSONFieldNames(reflect.TypeOf(armotypes.ProfileDataRequired{}))
	KnownProfileDataPatternFields = extractJSONFieldNames(reflect.TypeOf(armotypes.ProfileDataPattern{}))
)

func extractJSONFieldNames(t reflect.Type) map[string]bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	m := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			m[name] = true
		}
	}
	return m
}

// ValidateRawProfileDataRequired inspects raw, untyped profileDataRequired
// definitions (e.g. from an unstructured CRD or JSON/YAML map) before conversion
// to armotypes.ProfileDataRequired discards unknown keys.
func ValidateRawProfileDataRequired(raw any) error {
	if raw == nil {
		return nil
	}
	rawMap, ok := toStringMap(raw)
	if !ok {
		return fmt.Errorf("profileDataRequired must be a map, got %T", raw)
	}

	for k, v := range rawMap {
		if !KnownProfileDataSurfaces[k] {
			return fmt.Errorf("profileDataRequired: unknown field %q", k)
		}
		if v == nil {
			continue
		}
		if err := validateRawProfileDataField(k, v); err != nil {
			return err
		}
	}
	return nil
}

func validateRawProfileDataField(surface string, val any) error {
	if s, ok := val.(string); ok {
		if s != "all" {
			return fmt.Errorf("profileDataRequired.%s: string value must be \"all\", got %q", surface, s)
		}
		return nil
	}

	slice, ok := toSlice(val)
	if !ok {
		return fmt.Errorf("profileDataRequired.%s: expected \"all\" or pattern list, got %T", surface, val)
	}
	if len(slice) == 0 {
		return fmt.Errorf("profileDataRequired.%s: pattern list must not be empty", surface)
	}

	for i, pat := range slice {
		patMap, ok := toStringMap(pat)
		if !ok {
			return fmt.Errorf("profileDataRequired.%s[%d]: pattern must be an object, got %T", surface, i, pat)
		}
		if len(patMap) == 0 {
			return fmt.Errorf("profileDataRequired.%s[%d]: empty pattern object", surface, i)
		}
		for pk := range patMap {
			if !KnownProfileDataPatternFields[pk] {
				return fmt.Errorf("profileDataRequired.%s[%d]: unknown field %q", surface, i, pk)
			}
		}
	}
	return nil
}

func toStringMap(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Map {
		res := make(map[string]any, val.Len())
		for _, key := range val.MapKeys() {
			res[fmt.Sprint(key.Interface())] = val.MapIndex(key).Interface()
		}
		return res, true
	}
	return nil, false
}

func toSlice(v any) ([]any, bool) {
	if s, ok := v.([]any); ok {
		return s, true
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Slice {
		res := make([]any, val.Len())
		for i := 0; i < val.Len(); i++ {
			res[i] = val.Index(i).Interface()
		}
		return res, true
	}
	return nil, false
}
