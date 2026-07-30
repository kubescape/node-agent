// Package statewrites validates and executes a rule's declarative `stateWrites`
// clause: the only way a CEL rule writes to the state store.
//
// Writes are declarative rather than a CEL setter function on purpose. A setter
// could be skipped by boolean short-circuiting, reordered by the static
// optimiser, and could never express "remember this without alerting" -- which is
// exactly what the first leg of a cross-event rule needs.
package statewrites

import (
	"fmt"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

// Compiled is a validated StateWrite ready for the rule loop.
//
// EventType is utils.EventType, not armotypes.EventType: the rule loop compares
// against utils.EventType, and doing the conversion once here keeps the
// comparison typed rather than a string cast at every event.
type Compiled struct {
	EventType utils.EventType
	Scope     armotypes.StateScope
	Name      string
	Key       string
	When      string
	Value     map[string]string
	TTL       time.Duration
}

// nodeAgentScopes are the scopes node-agent can resolve. identity is
// operator-only: there is no caller identity on an eBPF event.
var nodeAgentScopes = map[armotypes.StateScope]struct{}{
	armotypes.StateScopeContainer: {},
	armotypes.StateScopePod:       {},
	armotypes.StateScopeNode:      {},
}

// Validate checks one write and converts it for the rule loop.
//
// Everything here fails at rule load rather than at runtime, because every one of
// these mistakes otherwise produces a rule that loads cleanly and silently never
// fires -- the worst possible failure for a detection.
func Validate(w armotypes.StateWrite, ruleID string, maxTTL time.Duration) (Compiled, error) {
	fail := func(format string, args ...any) (Compiled, error) {
		return Compiled{}, fmt.Errorf("rule %s: stateWrites[%q]: "+format,
			append([]any{ruleID, w.Name}, args...)...)
	}

	if w.Name == "" {
		return fail("name must not be empty")
	}
	if strings.HasPrefix(w.Name, "_") {
		return fail("name must not begin with %q, which is reserved for engine provenance", "_")
	}

	// IsValidStateWriteEventType, not IsKnownEventType: the latter accepts
	// EventTypeAll, which is a rule-binding wildcard rather than an event stream,
	// so it would produce a write leg that never matches a concrete event.
	if !armotypes.IsValidStateWriteEventType(w.EventType) {
		return fail("eventType %q is not an event stream that can drive a write", w.EventType)
	}
	eventType := utils.EventType(w.EventType)
	if !utils.IsValidEventType(eventType) {
		return fail("eventType %q is not emitted by node-agent", w.EventType)
	}

	if _, ok := nodeAgentScopes[w.Scope]; !ok {
		return fail("scope %q is not resolvable by node-agent (want container, pod or node)", w.Scope)
	}

	ttl, err := time.ParseDuration(w.TTL)
	if err != nil {
		return fail("ttl %q is not a duration: %w", w.TTL, err)
	}
	if ttl <= 0 {
		return fail("ttl %q must be positive; an entry born expired is a silently dead rule", w.TTL)
	}
	if ttl > maxTTL {
		logger.L().Warning("statewrites - clamping ttl to the configured maximum",
			helpers.String("rule", ruleID),
			helpers.String("name", w.Name),
			helpers.String("requested", ttl.String()),
			helpers.String("maxTtl", maxTTL.String()))
		ttl = maxTTL
	}

	var values map[string]string
	if len(w.Value) > 0 {
		values = make(map[string]string, len(w.Value))
		for k, v := range w.Value {
			if k == "" {
				return fail("value keys must not be empty")
			}
			if strings.HasPrefix(k, "_") {
				return fail("value key %q must not begin with %q, which is reserved for engine provenance", k, "_")
			}
			s, ok := v.(string)
			if !ok {
				return fail("value %q must be a CEL expression string, got %T", k, v)
			}
			values[k] = s
		}
	}

	return Compiled{
		EventType: eventType,
		Scope:     w.Scope,
		Name:      w.Name,
		Key:       w.Key,
		When:      w.When,
		Value:     values,
		TTL:       ttl,
	}, nil
}

// ValidateAll validates a rule's whole clause and returns the name -> scope map
// that reads resolve against.
//
// A name must map to exactly one scope. Reads take no scope argument -- they infer
// it from the name -- so the same name in two scopes would make every read of it
// ambiguous. Declaring one name across several event types in the SAME scope is
// the normal bidirectional idiom and is allowed.
func ValidateAll(writes []armotypes.StateWrite, ruleID string, maxTTL time.Duration) ([]Compiled, map[string]armotypes.StateScope, error) {
	if len(writes) == 0 {
		return nil, nil, nil
	}

	compiled := make([]Compiled, 0, len(writes))
	scopeOf := make(map[string]armotypes.StateScope, len(writes))

	for _, w := range writes {
		c, err := Validate(w, ruleID, maxTTL)
		if err != nil {
			return nil, nil, err
		}
		if existing, ok := scopeOf[c.Name]; ok && existing != c.Scope {
			return nil, nil, fmt.Errorf(
				"rule %s: stateWrites[%q]: declared in both scope %q and scope %q; a name must have exactly one scope because reads infer it from the name",
				ruleID, c.Name, existing, c.Scope)
		}
		scopeOf[c.Name] = c.Scope
		compiled = append(compiled, c)
	}

	return compiled, scopeOf, nil
}
