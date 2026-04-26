package prefilter

import (
	"encoding/json"
	"slices"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
	Ports           []uint16   // SSH, network — skip if port is NOT in list
	Dir             Direction  // HTTP — DirInbound or DirOutbound
	MethodMask      MethodMask // HTTP — bitmask of allowed methods
}

// rawParams is the JSON/YAML-decodable shape of pre-filter parameters.
// encoding/json handles all numeric type coercion (float64, int, int64, etc.)
type rawParams struct {
	IgnorePrefixes  []string `json:"ignorePrefixes"`
	IncludePrefixes []string `json:"includePrefixes"`
	Ports           []uint16 `json:"ports"`
	Direction       string   `json:"direction"`
	Methods         []string `json:"methods"`
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

	buf, err := json.Marshal(merged)
	if err != nil {
		logger.L().Warning("prefilter: failed to marshal params", helpers.Error(err))
		return nil
	}
	var raw rawParams
	if err := json.Unmarshal(buf, &raw); err != nil {
		logger.L().Warning("prefilter: failed to unmarshal params", helpers.Error(err))
		return nil
	}

	p := &Params{}
	hasFilter := false

	if len(raw.IgnorePrefixes) > 0 {
		p.IgnorePrefixes = trimTrailingSlash(raw.IgnorePrefixes)
		hasFilter = true
	}

	if len(raw.IncludePrefixes) > 0 {
		p.IncludePrefixes = trimTrailingSlash(raw.IncludePrefixes)
		hasFilter = true
	}

	if len(raw.Ports) > 0 {
		p.Ports = raw.Ports
		hasFilter = true
	}

	if raw.Direction != "" {
		p.Dir = parseDirection(strings.ToLower(raw.Direction))
		if p.Dir != DirNone {
			hasFilter = true
		}
	}

	if len(raw.Methods) > 0 {
		for _, m := range raw.Methods {
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
		return true // pass through if event field is indeterminate
	}

	if p.MethodMask != 0 && e.MethodBit != 0 && p.MethodMask&e.MethodBit == 0 {
		return true // pass through if event field is indeterminate
	}

	if e.Path != "" {
		if len(p.IncludePrefixes) > 0 && !hasAnyPrefix(e.Path, p.IncludePrefixes) {
			return true
		}
		if len(p.IgnorePrefixes) > 0 && hasAnyPrefix(e.Path, p.IgnorePrefixes) {
			return true
		}
	}

	if e.PortEligible && len(p.Ports) > 0 && !slices.Contains(p.Ports, e.DstPort) {
		return true
	}

	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if s == p || (len(s) > len(p) && s[len(p)] == '/' && s[:len(p)] == p) {
			return true
		}
	}
	return false
}

func trimTrailingSlash(prefixes []string) []string {
	result := make([]string, len(prefixes))
	for i, p := range prefixes {
		result[i] = strings.TrimRight(p, "/")
	}
	return result
}
