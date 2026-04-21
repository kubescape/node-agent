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
// Passed by value, stack-allocated, extracted once before the rule loop and
// reused across all rules.
type EventFields struct {
	Path string // file path (open) or exe path (exec); empty otherwise
	// Exec-only fields; empty for other event types.
	// Comm and Pcomm are kernel-truncated to 15 chars.
	ParentExePath string
	Comm          string
	Pcomm         string
	DstPort       uint16     // destination port from network/SSH event
	Dir           Direction  // pre-computed from HTTP direction string
	MethodBit     MethodMask // pre-computed from HTTP method string
	PortEligible  bool       // true for SSH/network events (port filter applies)
	Extracted     bool       // true after extractEventFields has run
}

// SetDirection converts a direction string to its compact representation.
func (f *EventFields) SetDirection(s string) {
	f.Dir = parseDirection(s)
}

// SetMethod converts an HTTP method string to its bitmask representation.
func (f *EventFields) SetMethod(method string) {
	f.MethodBit = methodToBit(method)
}

// processKey pairs a kernel-truncated process name with its full exe path.
// Both fields must match for an exclude entry to suppress an event.
type processKey struct {
	Name string
	Path string
}

// Params holds parsed, typed parameters for cheap pre-CEL filtering.
// Parsed once at rule binding time. A non-nil *Params always has at least
// one active filter.
type Params struct {
	IgnorePrefixes         []string                // open, exec — skip if path starts with prefix
	IncludePrefixes        []string                // open, exec — skip if path does NOT match any prefix
	ExcludeProcesses       map[processKey]struct{} // exec — skip if (comm, exepath) matches
	ExcludeParentProcesses map[processKey]struct{} // exec — skip if (pcomm, parent_exepath) matches
	Ports                  []uint16                // SSH, network — skip if port is NOT in list
	Dir                    Direction               // HTTP — DirInbound or DirOutbound
	MethodMask             MethodMask              // HTTP — bitmask of allowed methods
}

type rawProcessEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// rawParams is the JSON/YAML-decodable shape of pre-filter parameters.
// encoding/json handles all numeric type coercion (float64, int, int64, etc.)
type rawParams struct {
	IgnorePrefixes         []string          `json:"ignorePrefixes"`
	IncludePrefixes        []string          `json:"includePrefixes"`
	Ports                  []uint16          `json:"ports"`
	Direction              string            `json:"direction"`
	Methods                []string          `json:"methods"`
	ExcludeProcesses       []rawProcessEntry `json:"excludeProcesses"`
	ExcludeParentProcesses []rawProcessEntry `json:"excludeParentProcesses"`
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

	if m := buildProcessMap(raw.ExcludeProcesses, "excludeProcesses"); m != nil {
		p.ExcludeProcesses = m
		hasFilter = true
	}

	if m := buildProcessMap(raw.ExcludeParentProcesses, "excludeParentProcesses"); m != nil {
		p.ExcludeParentProcesses = m
		hasFilter = true
	}

	if !hasFilter {
		return nil
	}
	return p
}

// buildProcessMap converts a list of (name, path) entries to a lookup map.
// Entries missing either field are dropped; a single aggregated warning is
// emitted if any were dropped. Returns nil when no valid entries remain.
func buildProcessMap(entries []rawProcessEntry, field string) map[processKey]struct{} {
	if len(entries) == 0 {
		return nil
	}
	m := make(map[processKey]struct{}, len(entries))
	dropped := 0
	for _, entry := range entries {
		if entry.Name == "" || entry.Path == "" {
			dropped++
			continue
		}
		m[processKey{Name: entry.Name, Path: entry.Path}] = struct{}{}
	}
	if dropped > 0 {
		logger.L().Warning("prefilter: dropped entries with empty name or path",
			helpers.String("field", field),
			helpers.Int("dropped", dropped))
	}
	if len(m) == 0 {
		return nil
	}
	return m
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

	if len(p.ExcludeProcesses) > 0 && e.Comm != "" && e.Path != "" {
		if _, ok := p.ExcludeProcesses[processKey{Name: e.Comm, Path: e.Path}]; ok {
			return true
		}
	}

	if len(p.ExcludeParentProcesses) > 0 && e.Pcomm != "" && e.ParentExePath != "" {
		if _, ok := p.ExcludeParentProcesses[processKey{Name: e.Pcomm, Path: e.ParentExePath}]; ok {
			return true
		}
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
