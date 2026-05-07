package exporters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// EventFieldFilterConfig configures field-level filtering for exported alert events.
// AllowList takes precedence over DenyList. Both support dot notation (e.g. "spec.processTree").
type EventFieldFilterConfig struct {
	AllowList []string `json:"allowList,omitempty" mapstructure:"allowList"`
	DenyList  []string `json:"denyList,omitempty" mapstructure:"denyList"`
}

// EventFieldFilter applies allow/deny list filtering to JSON payloads.
type EventFieldFilter struct {
	allowSet map[string]struct{}
	denySet  map[string]struct{}
	useAllow bool
}

// NewEventFieldFilter creates a filter from config. Returns nil if no fields are configured.
func NewEventFieldFilter(config *EventFieldFilterConfig) *EventFieldFilter {
	if config == nil {
		return nil
	}
	if len(config.AllowList) == 0 && len(config.DenyList) == 0 {
		return nil
	}

	f := &EventFieldFilter{}
	if len(config.AllowList) > 0 {
		f.useAllow = true
		f.allowSet = make(map[string]struct{}, len(config.AllowList))
		for _, field := range config.AllowList {
			f.allowSet[field] = struct{}{}
		}
	} else {
		f.denySet = make(map[string]struct{}, len(config.DenyList))
		for _, field := range config.DenyList {
			f.denySet[field] = struct{}{}
		}
	}
	return f
}

// FilterJSON applies the field filter to marshaled JSON bytes and returns filtered bytes.
func (f *EventFieldFilter) FilterJSON(data []byte) ([]byte, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("field filter: failed to unmarshal: %w", err)
	}

	if f.useAllow {
		m = applyAllowList(m, f.allowSet)
	} else {
		for key := range f.denySet {
			parts := strings.SplitN(key, ".", 2)
			if len(parts) == 1 {
				delete(m, key)
			} else {
				removePath(m, parts[0], parts[1])
			}
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("field filter: failed to marshal: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func applyAllowList(m map[string]any, allowSet map[string]struct{}) map[string]any {
	groups := make(map[string]map[string]struct{})
	for path := range allowSet {
		parts := strings.SplitN(path, ".", 2)
		topKey := parts[0]
		if _, ok := groups[topKey]; !ok {
			groups[topKey] = make(map[string]struct{})
		}
		if len(parts) > 1 {
			groups[topKey][parts[1]] = struct{}{}
		}
	}

	result := make(map[string]any)
	for topKey, subSet := range groups {
		val, exists := m[topKey]
		if !exists {
			continue
		}
		if _, ok := allowSet[topKey]; ok {
			result[topKey] = val
			continue
		}
		if len(subSet) > 0 {
			if nested, ok := val.(map[string]any); ok {
				result[topKey] = applyAllowList(nested, subSet)
			} else if slice, ok := val.([]any); ok {
				newSlice := make([]any, 0, len(slice))
				for _, item := range slice {
					if itemMap, ok := item.(map[string]any); ok {
						filtered := applyAllowList(itemMap, subSet)
						if len(filtered) > 0 {
							newSlice = append(newSlice, filtered)
						}
					} else {
						newSlice = append(newSlice, item)
					}
				}
				result[topKey] = newSlice
			} else {
				// scalar value (string, number, bool) — keep it as-is
				result[topKey] = val
			}
		}
	}
	return result
}

func removePath(m map[string]any, topKey, rest string) {
	val, exists := m[topKey]
	if !exists {
		return
	}
	parts := strings.SplitN(rest, ".", 2)
	if nested, ok := val.(map[string]any); ok {
		if len(parts) == 1 {
			delete(nested, rest)
		} else {
			removePath(nested, parts[0], parts[1])
		}
	} else if slice, ok := val.([]any); ok {
		for _, item := range slice {
			if itemMap, ok := item.(map[string]any); ok {
				if len(parts) == 1 {
					delete(itemMap, rest)
				} else {
					removePath(itemMap, parts[0], parts[1])
				}
			}
		}
	}
}
