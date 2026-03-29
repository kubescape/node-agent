package prefilter

import (
	"slices"
	"strings"
)

// Direction represents an HTTP traffic direction as a compact integer.
type Direction uint8

const (
	DirNone     Direction = 0
	DirInbound  Direction = 1
	DirOutbound Direction = 2
)

func parseDirection(s string) Direction {
	switch s {
	case "inbound":
		return DirInbound
	case "outbound":
		return DirOutbound
	default:
		return DirNone
	}
}

// MethodMask is a bitmask of HTTP methods for O(1) membership testing.
type MethodMask uint16

const (
	MethodGET     MethodMask = 1 << iota
	MethodHEAD               // 2
	MethodPOST               // 4
	MethodPUT                // 8
	MethodPATCH              // 16
	MethodDELETE             // 32
	MethodCONNECT            // 64
	MethodOPTIONS            // 128
	MethodTRACE              // 256
)

func methodToBit(method string) MethodMask {
	switch method {
	case "GET":
		return MethodGET
	case "HEAD":
		return MethodHEAD
	case "POST":
		return MethodPOST
	case "PUT":
		return MethodPUT
	case "PATCH":
		return MethodPATCH
	case "DELETE":
		return MethodDELETE
	case "CONNECT":
		return MethodCONNECT
	case "OPTIONS":
		return MethodOPTIONS
	case "TRACE":
		return MethodTRACE
	default:
		return 0
	}
}

// EventFields holds event data extracted once per event for pre-filtering.
// Passed by value (stack-allocated, ~28 bytes) — extracted once before the
// rule loop, reused across all rules.
type EventFields struct {
	Path         string     // file/exec path (empty if not applicable)
	DstPort      uint16     // destination port from network/SSH event
	Dir          Direction  // pre-computed from HTTP direction string
	MethodBit    MethodMask // pre-computed from HTTP method string
	PortEligible bool       // true for SSH/network events (port filter applies)
	Extracted    bool       // true after extractEventFields has run
}

// SetDirection converts a direction string to its compact representation.
func (f *EventFields) SetDirection(s string) {
	f.Dir = parseDirection(s)
}

// SetMethod converts an HTTP method string to its bitmask representation.
func (f *EventFields) SetMethod(method string) {
	f.MethodBit = methodToBit(method)
}

// Params holds parsed, typed parameters for cheap pre-CEL filtering.
// Parsed once at rule binding time. A non-nil *Params always has at least
// one active filter.
type Params struct {
	IgnorePrefixes  []string   // open, exec — skip if path starts with prefix
	IncludePrefixes []string   // open, exec — skip if path does NOT match any prefix
	AllowedPorts    []uint16   // SSH, network — skip if port IS in list
	Dir             Direction  // HTTP — DirInbound or DirOutbound
	MethodMask      MethodMask // HTTP — bitmask of allowed methods
}

// ParseWithDefaults merges pre-filter parameters from two sources:
//   - ruleState: defaults from the rule library YAML (Rule.State)
//   - bindingParams: per-deployment overrides from the rule binding CRD
//
// Binding parameters override rule state for the same key.
// Returns nil if no pre-filterable parameters are present.
func ParseWithDefaults(ruleState map[string]any, bindingParams map[string]any) *Params {
	if len(ruleState) == 0 && len(bindingParams) == 0 {
		return nil
	}

	merged := make(map[string]any, len(ruleState)+len(bindingParams))
	for k, v := range ruleState {
		merged[k] = v
	}
	for k, v := range bindingParams {
		merged[k] = v // binding overrides state
	}

	p := &Params{}
	hasFilter := false

	if v, ok := toStringSlice(merged["ignorePrefixes"]); ok && len(v) > 0 {
		p.IgnorePrefixes = ensureTrailingSlash(v)
		hasFilter = true
	}

	if v, ok := toStringSlice(merged["includePrefixes"]); ok && len(v) > 0 {
		p.IncludePrefixes = ensureTrailingSlash(v)
		hasFilter = true
	}

	if v, ok := toUint16Slice(merged["allowedPorts"]); ok && len(v) > 0 {
		p.AllowedPorts = v
		hasFilter = true
	}

	if v, ok := merged["direction"].(string); ok && v != "" {
		p.Dir = parseDirection(strings.ToLower(v))
		if p.Dir != DirNone {
			hasFilter = true
		}
	}

	if v, ok := toStringSlice(merged["methods"]); ok && len(v) > 0 {
		for _, m := range v {
			p.MethodMask |= methodToBit(strings.ToUpper(m))
		}
		if p.MethodMask != 0 {
			hasFilter = true
		}
	}

	if !hasFilter {
		return nil
	}
	return p
}

// ShouldSkip returns true if the event should be skipped.
// Hot path — integer/bitmask comparisons only, no allocations.
// Safe to call on nil receiver (returns false).
func (p *Params) ShouldSkip(e EventFields) bool {
	if p == nil {
		return false
	}

	if p.Dir != DirNone && e.Dir != DirNone && e.Dir != p.Dir {
		return true
	}

	if p.MethodMask != 0 && e.MethodBit != 0 && p.MethodMask&e.MethodBit == 0 {
		return true
	}

	if e.Path != "" {
		if len(p.IncludePrefixes) > 0 && !hasAnyPrefix(e.Path, p.IncludePrefixes) {
			return true
		}
		if len(p.IgnorePrefixes) > 0 && hasAnyPrefix(e.Path, p.IgnorePrefixes) {
			return true
		}
	}

	if e.PortEligible && len(p.AllowedPorts) > 0 && slices.Contains(p.AllowedPorts, e.DstPort) {
		return true
	}

	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func toStringSlice(v interface{}) ([]string, bool) {
	if v == nil {
		return nil, false
	}
	switch val := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result, len(result) > 0
	case []string:
		cp := make([]string, len(val))
		copy(cp, val)
		return cp, len(val) > 0
	}
	return nil, false
}

func toUint16Slice(v interface{}) ([]uint16, bool) {
	if v == nil {
		return nil, false
	}
	switch vals := v.(type) {
	case []interface{}:
		result := make([]uint16, 0, len(vals))
		for _, item := range vals {
			if f, ok := item.(float64); ok && f >= 0 && f <= 65535 {
				result = append(result, uint16(f))
			}
		}
		return result, len(result) > 0
	case []uint16:
		cp := make([]uint16, len(vals))
		copy(cp, vals)
		return cp, len(vals) > 0
	}
	return nil, false
}

func ensureTrailingSlash(prefixes []string) []string {
	for i, p := range prefixes {
		if !strings.HasSuffix(p, "/") {
			prefixes[i] = p + "/"
		}
	}
	return prefixes
}
