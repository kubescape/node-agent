package statewrites

import (
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
)

// evaluator is the slice of the CEL evaluator the executor needs. Declared here
// rather than imported so this package does not depend on the whole rule engine.
type evaluator interface {
	EvaluateBoolExpressionWithContext(evalContext map[string]any, expression string) (bool, error)
	EvaluateStringExpressionWithContext(evalContext map[string]any, expression string) (string, error)
}

// Executor applies a rule's validated write clause for one event.
type Executor struct {
	store   *rulestate.Store
	eval    evaluator
	metrics rulestate.Metrics
}

func NewExecutor(store *rulestate.Store, eval evaluator, metrics rulestate.Metrics) *Executor {
	if metrics == nil {
		metrics = rulestate.NoopMetrics{}
	}
	return &Executor{store: store, eval: eval, metrics: metrics}
}

// ScopeIDs resolves this event's ID for every scope node-agent supports.
//
// Scope IDs are always derived here from the event, never from rule input, which
// is what stops a rule reaching another container's bucket. A host / cgroup-0
// process has no container ID and maps to the explicit host bucket rather than to
// the empty string, which would otherwise collide with node scope.
func ScopeIDs(enriched *events.EnrichedEvent) map[armotypes.StateScope]string {
	ids := map[armotypes.StateScope]string{
		armotypes.StateScopeContainer: rulestate.ContainerScopeID(enriched.ContainerID),
		armotypes.StateScopeNode:      rulestate.NodeScopeID(),
	}
	if ns, pod := podIdentity(enriched); pod != "" {
		ids[armotypes.StateScopePod] = rulestate.PodScopeID(ns, pod)
	}
	return ids
}

func podIdentity(enriched *events.EnrichedEvent) (string, string) {
	if enriched.Event == nil {
		return "", ""
	}
	return enriched.Event.GetNamespace(), enriched.Event.GetPod()
}

// exePathGetter and cwdGetter are satisfied by the process-bearing event types
// (exec, open, dns, ...) but not by all of them, so they are probed rather than
// required. An event without them simply stores no path.
type exePathGetter interface{ GetExePath() string }
type cwdGetter interface{ GetCwd() string }

// Apply evaluates every write whose event type matches this event and stores the
// ones whose guard passes.
//
// It must be called AFTER the predicate has been evaluated. If a write landed
// first, a rule that reads and writes the same name on the same event type would
// satisfy itself from its own write on a single event.
//
// A store rejection is logged at debug and counted, never propagated: a full
// store must degrade correlation, not break alerting.
func (e *Executor) Apply(
	compiled []Compiled,
	ruleID string,
	enriched *events.EnrichedEvent,
	evalContext map[string]any,
	eventTime time.Time,
) {
	if e == nil || e.store == nil || len(compiled) == 0 || evalContext == nil {
		return
	}
	eventType := enriched.Event.GetEventType()
	scopeIDs := ScopeIDs(enriched)

	for _, w := range compiled {
		if w.EventType != eventType {
			continue
		}

		if w.When != "" {
			ok, err := e.eval.EvaluateBoolExpressionWithContext(evalContext, w.When)
			if err != nil {
				logger.L().Debug("statewrites - guard evaluation failed",
					helpers.Error(err),
					helpers.String("rule", ruleID),
					helpers.String("name", w.Name))
				e.metrics.ReportStateWriteRejected(ruleID, "guard_error")
				continue
			}
			if !ok {
				continue
			}
		}

		scopeID, ok := scopeIDs[w.Scope]
		if !ok {
			// pod scope on an event with no pod identity, e.g. a host process.
			e.metrics.ReportStateWriteRejected(ruleID, "scope_unresolved")
			continue
		}

		key := ""
		if w.Key != "" {
			k, err := e.eval.EvaluateStringExpressionWithContext(evalContext, w.Key)
			if err != nil {
				logger.L().Debug("statewrites - key evaluation failed",
					helpers.Error(err),
					helpers.String("rule", ruleID),
					helpers.String("name", w.Name))
				e.metrics.ReportStateWriteRejected(ruleID, "key_error")
				continue
			}
			key = k
		}

		entry := &rulestate.Entry{
			RuleID:    ruleID,
			Name:      w.Name,
			Scope:     w.Scope,
			ScopeID:   scopeID,
			Key:       key,
			EventType: armotypes.EventType(w.EventType),
			Timestamp: eventTime,
			ExpiresAt: eventTime.Add(w.TTL),
			Process:   processOf(enriched),
			Value:     e.evaluateValues(w, ruleID, evalContext),
		}

		if err := e.store.Set(entry); err != nil {
			logger.L().Debug("statewrites - store rejected the write",
				helpers.Error(err),
				helpers.String("rule", ruleID),
				helpers.String("name", w.Name))
		}
	}
}

func (e *Executor) evaluateValues(w Compiled, ruleID string, evalContext map[string]any) map[string]any {
	if len(w.Value) == 0 {
		return nil
	}
	out := make(map[string]any, len(w.Value))
	for k, expr := range w.Value {
		v, err := e.eval.EvaluateStringExpressionWithContext(evalContext, expr)
		if err != nil {
			logger.L().Debug("statewrites - value evaluation failed",
				helpers.Error(err),
				helpers.String("rule", ruleID),
				helpers.String("name", w.Name),
				helpers.String("valueKey", k))
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// processOf snapshots the acting process onto the entry, so an alert on the far
// leg of a chain can describe the process at the near leg -- which by then may be
// long gone.
func processOf(enriched *events.EnrichedEvent) *armotypes.Process {
	p := &armotypes.Process{
		PID:  enriched.PID,
		PPID: enriched.PPID,
	}
	if e, ok := enriched.Event.(utils.EnrichEvent); ok {
		if p.PID == 0 {
			p.PID = e.GetPID()
		}
		if p.PPID == 0 {
			p.PPID = e.GetPpid()
		}
		p.Comm = e.GetComm()
		p.Pcomm = e.GetPcomm()
	}
	if e, ok := enriched.Event.(exePathGetter); ok {
		p.Path = e.GetExePath()
	}
	if e, ok := enriched.Event.(cwdGetter); ok {
		p.Cwd = e.GetCwd()
	}
	return p
}
