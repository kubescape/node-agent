package rulemanager

import (
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

// compileStateWrites validates a rule's write clause and returns the compiled
// writes plus the name -> scope map that its reads resolve against.
//
// Compilation happens per event rather than once at rule load. That is deliberate:
// it is pure string and duration parsing (the CEL expressions themselves are
// compiled and cached by the evaluator, keyed by expression text), it only runs
// for rules that declare writes -- a small minority -- and doing it here avoids a
// cache that would have to be invalidated on every CRD change. Rules reach the
// loop from two different paths, only one of which populates load-time derived
// fields, so a cached field would be silently empty for host rules.
//
// A rule whose clause fails validation is treated as having no writes, and the
// failure is logged. It is not fatal: one malformed rule must not stop the other
// forty from evaluating.
func (rm *RuleManager) compileStateWrites(rule *typesv1.Rule) ([]statewrites.Compiled, map[string]armotypes.StateScope) {
	if len(rule.StateWrites) == 0 {
		return nil, nil
	}

	compiled, scopeOf, err := statewrites.ValidateAll(rule.StateWrites, rule.ID, rm.cfg.CelStateStore.MaxTTL)
	if err != nil {
		logger.L().Error("RuleManager - invalid stateWrites clause; the rule will not correlate",
			helpers.Error(err), helpers.String("rule", rule.ID))
		return nil, nil
	}
	return compiled, scopeOf
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
