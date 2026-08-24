package rulemanager

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/state"
	"github.com/kubescape/node-agent/pkg/rulemanager/statewrites"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

// compiledWrites is one cached compilation of a rule's write clause. A failed
// compilation is cached too, as a nil compiled slice -- otherwise a malformed
// rule would re-validate and re-log on every matching event.
type compiledWrites struct {
	compiled []statewrites.Compiled
	scopeOf  map[string]armotypes.StateScope
}

// compileStateWrites validates a rule's write clause and returns the compiled
// writes plus the name -> scope map that its reads resolve against.
//
// The result is cached, keyed by rule ID AND a fingerprint of the clause itself.
// Compilation cannot live on the Rule as a load-time field: rules reach the loop
// from two different paths and only the Kubernetes binding path populates
// load-time derived fields, so such a field would be silently empty for host
// rules. Fingerprinting instead of invalidating sidesteps that entirely -- an
// edited clause simply hashes differently and recompiles, from either path, with
// no invalidation hook to forget to call.
//
// Caching is what makes the logging below safe. Validation errors and TTL
// clamping used to be logged on EVERY matching event, so a single misconfigured
// rule could emit thousands of identical lines per second on a busy node. Now
// each distinct version of a clause is compiled, and therefore logged, once.
//
// A rule whose clause fails validation is treated as having no writes. It is not
// fatal: one malformed rule must not stop the other forty from evaluating.
func (rm *RuleManager) compileStateWrites(rule *typesv1.Rule) ([]statewrites.Compiled, map[string]armotypes.StateScope) {
	if len(rule.StateWrites) == 0 {
		return nil, nil
	}

	key := stateWritesCacheKey(rule)
	if cached, ok := rm.stateWritesCache.Get(key); ok {
		return cached.compiled, cached.scopeOf
	}

	compiled, scopeOf, err := statewrites.ValidateAll(rule.StateWrites, rule.ID, rm.cfg.CelStateStore.MaxTTL)
	if err != nil {
		logger.L().Error("RuleManager - invalid stateWrites clause; the rule will not correlate",
			helpers.Error(err), helpers.String("rule", rule.ID))
		compiled, scopeOf = nil, nil
	}
	rm.stateWritesCache.Add(key, &compiledWrites{compiled: compiled, scopeOf: scopeOf})
	return compiled, scopeOf
}

// stateWritesCacheKey identifies one version of one rule's write clause.
//
// It hashes every field validation reads, so any edit that could change the
// compiled result also changes the key. Hashing is far cheaper than the parsing
// and map building it replaces, and only rules that declare writes reach it.
func stateWritesCacheKey(rule *typesv1.Rule) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(rule.ID))
	for i := range rule.StateWrites {
		w := &rule.StateWrites[i]
		for _, part := range []string{
			string(w.EventType), string(w.Scope), w.Name, w.Key, w.When, w.TTL,
		} {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
		// Value is a map, so iteration order varies; hash it order-independently
		// by XOR-ing each pair's own digest into a running total.
		var values uint64
		for k, v := range w.Value {
			p := fnv.New64a()
			_, _ = p.Write([]byte(k))
			_, _ = p.Write([]byte{0})
			_, _ = p.Write([]byte(fmt.Sprint(v)))
			values ^= p.Sum64()
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], values)
		_, _ = h.Write(buf[:])
	}
	return strconv.FormatUint(h.Sum64(), 16)
}

func hasWriteFor(compiled []statewrites.Compiled, eventType utils.EventType) bool {
	for _, w := range compiled {
		if w.EventType == eventType {
			return true
		}
	}
	return false
}

// seedStateContext installs the per-rule state receiver into the eval context.
//
// The ancestor walk is passed as a closure and resolved lazily inside the
// accessor: most rules never call has_ancestor, and walking the process tree per
// event per rule would be a real cost for a feature few rules use.
func (rm *RuleManager) seedStateContext(
	evalContext map[string]any,
	rule *typesv1.Rule,
	enrichedEvent *events.EnrichedEvent,
	scopeOf map[string]armotypes.StateScope,
	tracker *state.ReadTracker,
) {
	evalContext[state.AccessorContextKey] = state.NewAccessor(
		rm.stateStore,
		rule.ID,
		scopeOf,
		statewrites.ScopeIDs(enrichedEvent),
		func() []uint32 {
			return rm.processManager.GetAncestorPIDs(
				enrichedEvent.PID, rm.cfg.CelStateStore.AncestorMaxDepth)
		},
		tracker,
		nil,
	)
}

// stateMetrics adapts the node-agent metrics manager to rulestate.Metrics.
//
// It is a separate type so pkg/rulestate stays free of any metrics dependency and
// remains unit-testable on its own.
type stateMetrics struct {
	mm metricsmanager.MetricsManager
}

func newStateMetrics(mm metricsmanager.MetricsManager) *stateMetrics {
	return &stateMetrics{mm: mm}
}

func (s *stateMetrics) ReportStateWrite(ruleID, result string) {
	if s.mm != nil {
		s.mm.ReportStateWrite(ruleID, result)
	}
}

func (s *stateMetrics) ReportStateWriteRejected(ruleID, reason string) {
	if s.mm != nil {
		s.mm.ReportStateWriteRejected(ruleID, reason)
	}
}

func (s *stateMetrics) ReportStateExpired(n int) {
	if s.mm != nil {
		s.mm.ReportStateExpired(n)
	}
}

func (s *stateMetrics) ReportStatePurged(n int) {
	if s.mm != nil {
		s.mm.ReportStatePurged(n)
	}
}

func (s *stateMetrics) ReportStateEntries(scope string, n int) {
	if s.mm != nil {
		s.mm.ReportStateEntries(scope, n)
	}
}
