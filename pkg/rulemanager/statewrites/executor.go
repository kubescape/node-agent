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

// IncrementSink receives the entry each increment on an event produced. The
// rule loop passes the event's state accessor, so the expression that follows
// reads the count its own increment returned rather than a store value another
// worker may have advanced in between.
type IncrementSink interface {
	RecordIncrement(name, key string, e *rulestate.Entry)
}

// ApplyIncrements runs the increment writes for this event. It is called BEFORE
// the rule expression, so the count the expression reads includes this event:
// on the Nth qualifying event state.count() is N, which is what `>= N` means to
// an author. Only OpIncrement writes run here; Apply handles the rest.
func (e *Executor) ApplyIncrements(
	compiled []Compiled,
	ruleID string,
	enriched *events.EnrichedEvent,
	evalContext map[string]any,
	eventTime time.Time,
	sink IncrementSink,
) {
	e.run(compiled, ruleID, enriched, evalContext, eventTime, func(op Op) bool { return op == OpIncrement }, sink)
}

// Apply runs the set and clear writes for this event.
//
// It must be called AFTER the predicate has been evaluated. If a set landed
// first, a rule that reads and writes the same name on the same event type would
// satisfy itself from its own write on a single event. Increments are excluded
// here: they run in ApplyIncrements, before the predicate, by design.
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
	e.run(compiled, ruleID, enriched, evalContext, eventTime, func(op Op) bool { return op != OpIncrement }, nil)
}

func (e *Executor) run(
	compiled []Compiled,
	ruleID string,
	enriched *events.EnrichedEvent,
	evalContext map[string]any,
	eventTime time.Time,
	inPhase func(Op) bool,
	sink IncrementSink,
) {
	if e == nil || e.store == nil || len(compiled) == 0 || evalContext == nil {
		return
	}
	// podIdentity and processOf below both tolerate a nil Event; without this the
	// very next line would panic instead, so the package's nil handling would be
	// inconsistent. Not reachable from the rule loop, which dereferences Event
	// earlier, but the exported entry points should not depend on that.
	if enriched == nil || enriched.Event == nil {
		return
	}
	// RuleEventType, not GetEventType: a forwarded DNS query is emitted by the
	// tracer as "dns" but is selected by rules as "dnsQuery". Comparing the raw
	// tracer type here would route it to "dns" writes, which is the opposite of
	// what the rule's own expressions see.
	eventType := utils.RuleEventType(enriched.Event)
	scopeIDs := ScopeIDs(enriched)

	for _, w := range compiled {
		if w.EventType != eventType || !inPhase(w.Op) {
			continue
		}

		scopeID, key, ok := e.resolve(w, ruleID, scopeIDs, evalContext)
		if !ok {
			continue
		}

		switch w.Op {
		case OpClear:
			e.store.Delete(ruleID, scopeID, w.Name, key)
			continue
		case OpIncrement:
			entry := e.newEntry(w, ruleID, scopeID, key, enriched, eventTime, nil)
			stored, err := e.store.Incr(entry, 1)
			if err != nil {
				logger.L().Debug("statewrites - store rejected the increment",
					helpers.Error(err),
					helpers.String("rule", ruleID),
					helpers.String("name", w.Name))
				continue
			}
			if sink != nil {
				sink.RecordIncrement(w.Name, key, stored)
			}
			continue
		}

		entry := e.newEntry(w, ruleID, scopeID, key, enriched, eventTime, e.evaluateValues(w, ruleID, evalContext))
		if err := e.store.Set(entry); err != nil {
			logger.L().Debug("statewrites - store rejected the write",
				helpers.Error(err),
				helpers.String("rule", ruleID),
				helpers.String("name", w.Name))
		}
	}
}

// resolve evaluates the guard, the scope and the key, which every operation
// shares. A false guard or a failed evaluation is reported as not ok; failures
// are counted so a write that never lands is visible.
func (e *Executor) resolve(
	w Compiled,
	ruleID string,
	scopeIDs map[armotypes.StateScope]string,
	evalContext map[string]any,
) (scopeID, key string, ok bool) {
	if w.When != "" {
		pass, err := e.eval.EvaluateBoolExpressionWithContext(evalContext, w.When)
		if err != nil {
			logger.L().Debug("statewrites - guard evaluation failed",
				helpers.Error(err),
				helpers.String("rule", ruleID),
				helpers.String("name", w.Name))
			e.metrics.ReportStateWriteRejected(ruleID, "guard_error")
			return "", "", false
		}
		if !pass {
			return "", "", false
		}
	}

	scopeID, found := scopeIDs[w.Scope]
	if !found {
		// pod scope on an event with no pod identity, e.g. a host process.
		e.metrics.ReportStateWriteRejected(ruleID, "scope_unresolved")
		return "", "", false
	}

	if w.Key != "" {
		k, err := e.eval.EvaluateStringExpressionWithContext(evalContext, w.Key)
		if err != nil {
			logger.L().Debug("statewrites - key evaluation failed",
				helpers.Error(err),
				helpers.String("rule", ruleID),
				helpers.String("name", w.Name))
			e.metrics.ReportStateWriteRejected(ruleID, "key_error")
			return "", "", false
		}
		key = k
	}
	return scopeID, key, true
}

func (e *Executor) newEntry(
	w Compiled,
	ruleID, scopeID, key string,
	enriched *events.EnrichedEvent,
	eventTime time.Time,
	values map[string]any,
) *rulestate.Entry {
	return &rulestate.Entry{
		RuleID:    ruleID,
		Name:      w.Name,
		Scope:     w.Scope,
		ScopeID:   scopeID,
		Key:       key,
		EventType: armotypes.EventType(w.EventType),
		Timestamp: eventTime,
		ExpiresAt: eventTime.Add(w.TTL),
		Process:   processOf(enriched),
		Value:     values,
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
