package rulemanager

import (
	"context"
	"crypto/md5"
	"fmt"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/hashicorp/golang-lru/v2/expirable"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/contextdetection/detectors"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/processtree"
	bindingcache "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/state"
	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/statewrites"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
)

type RuleManager struct {
	cfg                  config.Config
	ruleBindingCache     bindingcache.RuleBindingCache
	trackedContainers    mapset.Set[string]                  // key is k8sContainerID
	trackedContainerDone maps.SafeMap[string, chan struct{}] // key is k8sContainerID; closed when that specific registration is removed
	k8sClient            k8sclient.K8sClientInterface
	ctx                  context.Context
	objectCache          objectcache.ObjectCache
	exporter             exporters.Exporter
	metrics              metricsmanager.MetricsManager
	podToWlid            maps.SafeMap[string, string] // key is namespace/podName
	containerIdToShimPid maps.SafeMap[string, uint32]
	containerIdToPid     maps.SafeMap[string, uint32]
	enricher             types.Enricher
	processManager       processtree.ProcessTreeManager
	celEvaluator         cel.RuleEvaluator
	ruleCooldown         *rulecooldown.RuleCooldown
	adapterFactory       *ruleadapters.EventRuleAdapterFactory
	ruleFailureCreator   ruleadapters.RuleFailureCreatorInterface
	rulePolicyValidator  *RulePolicyValidator
	mntnsRegistry        contextdetection.Registry
	detectorManager      *detectors.DetectorManager
	alertLogDedup        *expirable.LRU[string, struct{}]
	alertLogDedupMu      sync.Mutex
	// stateWritesCache holds compiled write clauses, keyed by rule ID plus a
	// fingerprint of the clause, so an edited rule recompiles without an
	// invalidation hook. expirable.LRU is already concurrency-safe.
	stateWritesCache *expirable.LRU[string, *compiledWrites]
	stateStore       *rulestate.Store
	stateWrites      *statewrites.Executor
}

var _ RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(
	ctx context.Context,
	cfg config.Config,
	k8sClient k8sclient.K8sClientInterface,
	ruleBindingCache bindingcache.RuleBindingCache,
	objectCache objectcache.ObjectCache,
	exporter exporters.Exporter,
	metrics metricsmanager.MetricsManager,
	processManager processtree.ProcessTreeManager,
	dnsManager dnsmanager.DNSResolver,
	enricher types.Enricher,
	ruleCooldown *rulecooldown.RuleCooldown,
	adapterFactory *ruleadapters.EventRuleAdapterFactory,
	celEvaluator cel.RuleEvaluator,
	mntnsRegistry contextdetection.Registry,
	agentVersion string,
) (*RuleManager, error) {
	rulePolicyValidator := NewRulePolicyValidator(objectCache)
	detectorManager := detectors.NewDetectorManager(mntnsRegistry)

	r := &RuleManager{
		cfg:                 cfg,
		ctx:                 ctx,
		k8sClient:           k8sClient,
		trackedContainers:   mapset.NewSet[string](),
		ruleBindingCache:    ruleBindingCache,
		objectCache:         objectCache,
		exporter:            exporter,
		metrics:             metrics,
		adapterFactory:      adapterFactory,
		enricher:            enricher,
		processManager:      processManager,
		ruleCooldown:        ruleCooldown,
		celEvaluator:        celEvaluator,
		rulePolicyValidator: rulePolicyValidator,
		mntnsRegistry:       mntnsRegistry,
		detectorManager:     detectorManager,
		alertLogDedup:       expirable.NewLRU[string, struct{}](1000, nil, 60*time.Second),
		// No TTL: a compiled clause stays valid until the clause itself changes,
		// which changes the key. The bound is what evicts stale versions.
		stateWritesCache: expirable.NewLRU[string, *compiledWrites](512, nil, 0),
	}

	r.ruleFailureCreator = ruleadapters.NewRuleFailureCreator(enricher, dnsManager, adapterFactory, armotypes.AlertSourcePlatformK8sAgent, agentVersion, &r.containerIdToPid)

	// The state store lives here rather than in main.go because the rule loop is
	// its only writer and reader. Sweeping runs for the manager's lifetime.
	r.stateStore = rulestate.NewStore(cfg.CelStateStore, newStateMetrics(metrics))
	r.stateWrites = statewrites.NewExecutor(r.stateStore, celEvaluator, newStateMetrics(metrics))
	go r.stateStore.Run(ctx)

	// Compile the initial projection spec and start a goroutine that
	// recompiles whenever rule bindings change.
	r.recompileProjectionSpec()
	specNotify := make(chan bindingcache.RuleBindingNotify, 10)
	ruleBindingCache.AddNotifier(&specNotify)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-specNotify:
				// Drain any additional pending notifications so a burst of
				// rule-binding updates triggers only one recompile rather than
				// one per message (which would also risk filling the channel
				// and blocking AddHandler / RefreshRules callers).
				for len(specNotify) > 0 {
					<-specNotify
				}
				r.recompileProjectionSpec()
			}
		}
	}()

	return r, nil
}

// recompileProjectionSpec compiles a RuleProjectionSpec from all currently
// loaded rules and installs it on the ContainerProfileCache. Also runs
// soft-launch validation: rules with profileDependency>0 but no
// profileDataRequired emit an ERROR log (not rejected in default soft mode).
func (rm *RuleManager) recompileProjectionSpec() {
	rules := rm.ruleBindingCache.GetRuleCreator().CreateAllRules()

	// Soft-launch validation: rules with profileDependency>0 but no
	// profileDataRequired will receive an empty projection. Emit a DEBUG log
	// per rule and increment the metric; reject (filter out) only in strict mode.
	// A WARNING is emitted after the loop if no rule declares profileDataRequired,
	// which likely means the deployed CRD is outdated.
	filtered := rules[:0]
	var missingIDs []string
	for _, r := range rules {
		if r.ProfileDependency > 0 && r.ProfileDataRequired == nil {
			logger.L().Debug("rule has profileDependency but no profileDataRequired — projection will be empty for this rule",
				helpers.String("ruleID", r.ID),
				helpers.Int("profileDependency", int(r.ProfileDependency)))
			rm.metrics.IncMissingProfileDataRequired(r.ID)
			missingIDs = append(missingIDs, r.ID)
			if rm.cfg.ProfileProjection.StrictValidation {
				continue
			}
		}
		filtered = append(filtered, r)
	}
	if len(missingIDs) > 0 && len(missingIDs) == len(rules) {
		logger.L().Warning("no rule declares profileDataRequired — the deployed rules CRD may be outdated",
			helpers.Int("affectedRules", len(missingIDs)))
	}
	rules = filtered

	// Count rules with no profileDataRequired (pure event-shape rules).
	var undeclaredCount float64
	var undeclaredIDs []string
	for _, r := range rules {
		if r.ProfileDataRequired == nil {
			undeclaredCount++
			undeclaredIDs = append(undeclaredIDs, r.ID)
		}
	}
	rm.metrics.SetProjectionUndeclaredRules(undeclaredCount)

	spec := containerprofilecache.CompileSpec(rules)

	if rm.cfg.ProfileProjection.DetailedMetricsEnabled {
		rm.metrics.IncProjectionSpecCompile()
		rm.metrics.SetProjectionUndeclaredRulesDetail(undeclaredIDs)
		type namedField struct {
			name  string
			field *objectcache.FieldSpec
		}
		fields := []namedField{
			{"opens", &spec.Opens},
			{"execs", &spec.Execs},
			{"capabilities", &spec.Capabilities},
			{"syscalls", &spec.Syscalls},
			{"endpoints", &spec.Endpoints},
			{"egressDomains", &spec.EgressDomains},
			{"egressAddresses", &spec.EgressAddresses},
			{"ingressDomains", &spec.IngressDomains},
			{"ingressAddresses", &spec.IngressAddresses},
		}
		for _, nf := range fields {
			rm.metrics.SetProjectionSpecPatterns(nf.name, "prefix", float64(len(nf.field.Prefixes)))
			rm.metrics.SetProjectionSpecPatterns(nf.name, "suffix", float64(len(nf.field.Suffixes)))
			rm.metrics.SetProjectionSpecPatterns(nf.name, "exact", float64(len(nf.field.Exact)))
			rm.metrics.SetProjectionSpecPatterns(nf.name, "contains", float64(len(nf.field.Contains)))
			rm.metrics.SetProjectionSpecAllField(nf.name, nf.field.All)
		}
	}

	rm.objectCache.ContainerProfileCache().SetProjectionSpec(spec)
}

func (rm *RuleManager) startRuleManager(container *containercollection.Container, k8sContainerID string, done <-chan struct{}) {
	if utils.IsHostContainer(container) {
		logger.L().Debug("RuleManager - skipping shared data wait for host container",
			helpers.String("container ID", container.Runtime.ContainerID))
		// Skip podToWlid and shim PID setup for host containers as they don't have K8s metadata
		if err := rm.monitorContainer(container, k8sContainerID, done); err != nil {
			logger.L().Debug("RuleManager - stop monitor on host container",
				helpers.String("reason", err.Error()),
				helpers.String("container ID", container.Runtime.ContainerID),
				helpers.String("k8s container id", k8sContainerID))
		}
		return
	}

	sharedData, err := rm.waitForSharedContainerData(container.Runtime.ContainerID)
	if err != nil {
		logger.L().Error("RuleManager - failed to get shared container data", helpers.Error(err))
		return
	}

	podID := utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)
	if !rm.podToWlid.Has(podID) {
		w := sharedData.Wlid
		if w != "" {
			rm.podToWlid.Set(podID, w)
		} else {
			logger.L().Debug("RuleManager - failed to get workload identifier", helpers.String("k8s workload", container.K8s.PodName))
		}
	}

	if err := rm.monitorContainer(container, k8sContainerID, done); err != nil {
		logger.L().Debug("RuleManager - stop monitor on container", helpers.String("reason", err.Error()),
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s container id", k8sContainerID))
	}
}

func (rm *RuleManager) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
	if enrichedEvent.Duplicate {
		return
	}
	rm.enrichEventWithContext(enrichedEvent)

	var profileExists bool
	var details string
	namespace := enrichedEvent.Event.GetNamespace()
	pod := enrichedEvent.Event.GetPod()

	// Determine workload ID based on the context type
	isK8sContext := enrichedEvent.SourceContext == nil || enrichedEvent.SourceContext.Context() == contextdetection.Kubernetes

	if isK8sContext {
		if pod == "" || namespace == "" {
			return
		}
		podId := utils.CreateK8sPodID(namespace, pod)
		var ok bool
		details, ok = rm.podToWlid.Load(podId)
		if !ok {
			return
		}
	} else {
		// Host or Standalone context: use SourceContext.WorkloadID()
		if enrichedEvent.SourceContext == nil {
			return
		}
		details = enrichedEvent.SourceContext.WorkloadID()
		if details == "" {
			return
		}
	}

	// Retrieve rules based on context: K8s uses pod-based bindings
	var rules []typesv1.Rule
	if enrichedEvent.SourceContext == nil || enrichedEvent.SourceContext.Context() == contextdetection.Kubernetes {
		rules = rm.ruleBindingCache.ListRulesForPod(namespace, pod)
	} else {
		rules = rm.ruleBindingCache.GetRuleCreator().CreateRulesForContext(enrichedEvent.SourceContext.Context())
	}

	if len(rules) == 0 {
		rm.metrics.ReportAlertSuppressed("", "no_rules_for_pod")
		return
	}

	if !isSupportedEventType(rules, enrichedEvent) {
		return
	}

	_, apChecksum, err := profilehelper.GetProjectedContainerProfile(rm.objectCache, enrichedEvent.ContainerID)
	profileExists = err == nil

	// Early exit if monitoring is disabled for this context - skip rule evaluation
	if !rm.isMonitoringEnabledForContext(enrichedEvent.SourceContext) {
		return
	}

	eventType := enrichedEvent.Event.GetEventType()

	var eventFields prefilter.EventFields
	var evalContext map[string]any
	// One tracker per event, reset per rule. Allocating per event rather than per
	// rule keeps the common no-state path to a single allocation.
	stateTracker := &state.ReadTracker{}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if !RuleAppliesToContext(&rule, enrichedEvent.SourceContext) {
			continue
		}
		// Skip profile dependency checks for non-K8s contexts (profiles are K8s-specific)
		// Only K8s contexts should enforce profile dependencies
		if isK8sContext && !profileExists && rule.ProfileDependency == armotypes.Required {
			rm.metrics.ReportAlertSuppressed(rule.ID, "profile_incomplete")
			continue
		}

		ruleExpressions := rm.getRuleExpressions(rule, eventType)

		// Compile the write clause before the no-expressions bail-out below: a rule
		// may legitimately have NO ruleExpression for this event type and still need
		// to remember something. That is what makes write-without-alerting -- the
		// first leg of every cross-event rule -- possible.
		stateWrites, stateScopes := rm.compileStateWrites(&rule)
		writesThisEvent := hasWriteFor(stateWrites, eventType)

		if len(ruleExpressions) == 0 && !writesThisEvent {
			continue
		}

		// Pre-filter: skip CEL evaluation if parsed parameters exclude this event.
		if rule.Prefilter != nil {
			if !eventFields.Extracted {
				eventFields = extractEventFields(enrichedEvent.Event)
			}
			if rule.Prefilter.ShouldSkip(&eventFields) {
				rm.metrics.ReportRulePrefiltered(rule.ID)
				// A prefilter is built from the rule as a whole, in practice
				// mostly from its alerting leg's params, but it is applied to
				// every event type the rule touches. So a correlation rule whose
				// network leg carries ignorePrefixes or excludeProcesses has those
				// same params applied to its exec leg, and the write is dropped --
				// the chain then never forms, with nothing anywhere to say why.
				// Counting it is what turns that into a visible failure.
				rm.reportSuppressedWrite(&rule, stateWrites, eventType, "prefiltered")
				continue
			}
		}

		if rule.SupportPolicy && rm.validateRulePolicy(rule, enrichedEvent.Event, enrichedEvent.ContainerID) {
			rm.metrics.ReportAlertSuppressed(rule.ID, "policy")
			rm.reportSuppressedWrite(&rule, stateWrites, eventType, "policy")
			continue
		}

		if evalContext == nil {
			evalContext = rm.celEvaluator.CreateEvalContext(enrichedEvent)
		}

		// Rebuild the state receiver per rule: it carries the rule ID and the
		// rule's own declared-name scopes, so it cannot be shared between rules.
		// Resetting the tracker here is what stops rule N citing rule N-1's
		// entries as its own evidence.
		//
		// Only rules that actually declare state pay for this. seedStateContext
		// allocates a ScopeIDs map and an Accessor, and it ran for every rule on
		// every event -- on a node running forty stateless rules that was eighty
		// allocations per event for a feature none of them use.
		//
		// The delete is not optional. evalContext is built once per event and
		// reused across rules, so skipping the seed without clearing the key would
		// leave the PREVIOUS rule's accessor in place, and a stateless rule would
		// read another rule's state through it -- the one thing the receiver design
		// exists to make inexpressible.
		if len(stateScopes) > 0 {
			stateTracker.Reset()
			rm.seedStateContext(evalContext, &rule, enrichedEvent, stateScopes, stateTracker)
		} else {
			delete(evalContext, state.AccessorContextKey)
		}

		// From here on, alerting must not skip the write clause: writes are
		// evidence gathering, and dropping them because an alert was suppressed
		// would break the NEXT leg of the chain. The predicate and alert path is
		// therefore its own function -- its early exits return, and the writes
		// below still run.
		// processed mirrors the pre-refactor control flow exactly: the old loop
		// reached ReportRuleProcessed only by falling off the end, so an
		// eval error or a cooldown-suppressed alert did NOT count as processed.
		// Those were continues; they are returns now, so the metric has to be
		// gated or its meaning would silently change for every existing rule.
		//
		// It starts false, not true, for the same reason: the old loop also
		// continued at len(ruleExpressions) == 0 and never counted that rule. A
		// write-only leg -- a rule with a stateWrites clause but no
		// ruleExpression for THIS event type -- reaches here now where it
		// previously could not, so defaulting to true would inflate the counter
		// for exactly the case this feature introduces.
		processed := false
		if len(ruleExpressions) > 0 {
			processed = rm.evaluateRuleAndAlert(evaluateArgs{
				rule:            rule,
				ruleExpressions: ruleExpressions,
				enrichedEvent:   enrichedEvent,
				evalContext:     evalContext,
				eventType:       eventType,
				namespace:       namespace,
				pod:             pod,
				details:         details,
				apChecksum:      apChecksum,
				tracker:         stateTracker,
			})
		}

		if writesThisEvent {
			// Writes run AFTER the predicate, so a predicate only ever sees state
			// from EARLIER events. Otherwise a rule that reads and writes the same
			// name on the same event type would trivially satisfy itself.
			rm.stateWrites.Apply(stateWrites, rule.ID, enrichedEvent, evalContext,
				cel.ResolveEventTime(enrichedEvent))
		}

		if processed {
			rm.metrics.ReportRuleProcessed(rule.ID)
		}
	}
}

type evaluateArgs struct {
	rule            typesv1.Rule
	ruleExpressions []typesv1.RuleExpression
	enrichedEvent   *events.EnrichedEvent
	evalContext     map[string]any
	eventType       utils.EventType
	namespace       string
	pod             string
	details         string
	apChecksum      string
	tracker         *state.ReadTracker
}

// evaluateRuleAndAlert runs one rule's predicate and emits an alert if it fires.
//
// Split out of the rule loop so that every early exit in here is a return rather
// than a continue, which leaves the caller free to run the rule's state writes
// afterwards regardless of whether an alert was emitted or suppressed.
// The bool reports whether the path ran to completion. The caller uses it to
// decide whether to count the rule as processed, preserving the metric's
// pre-refactor meaning.
func (rm *RuleManager) evaluateRuleAndAlert(a evaluateArgs) bool {
	rule := a.rule
	enrichedEvent := a.enrichedEvent
	evalContext := a.evalContext
	eventType := a.eventType
	namespace := a.namespace
	pod := a.pod
	apChecksum := a.apChecksum

	startTime := time.Now()
	var shouldAlert bool
	var err error
	pprof.Do(context.Background(), pprof.Labels("rule", rule.ID), func(_ context.Context) {
		shouldAlert, err = rm.celEvaluator.EvaluateRuleWithContext(evalContext, eventType, a.ruleExpressions)
	})
	evaluationTime := time.Since(startTime)
	// Slow-path tracing: only emit a span when evaluation exceeded the threshold.
	// This protects the hot path from unconditional tracing overhead on millions of events/sec.
	// errCtx tracks the spanned context (when a rule.evaluate span fires) so the
	// failure log below inherits its trace_id/span_id — otherwise falls back to rm.ctx.
	errCtx := rm.ctx
	if evaluationTime >= otelsetup.SlowEvalThreshold() {
		evalCtx, span := otelsetup.Tracer().Start(rm.ctx, "rule.evaluate",
			trace.WithAttributes(
				attribute.String("rule.id", rule.ID),
				attribute.String("event.type", string(eventType)),
				attribute.String("container.id", enrichedEvent.ContainerID),
				attribute.Float64("eval.duration_ms", float64(evaluationTime.Milliseconds())),
				attribute.Bool("alert_fired", shouldAlert),
			))
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		rm.metrics.ReportRuleEvaluationTime(evalCtx, rule.ID, eventType, evaluationTime)
		span.End()
		errCtx = evalCtx
	} else {
		rm.metrics.ReportRuleEvaluationTime(rm.ctx, rule.ID, eventType, evaluationTime)
	}

	if err != nil {
		logger.L().Ctx(errCtx).Error("RuleManager.ReportEnrichedEvent - failed to evaluate rule", helpers.Error(err), helpers.String("rule", rule.ID), helpers.String("eventType", string(eventType)))
		rm.metrics.ReportAlertSuppressed(rule.ID, "eval_error")
		return false
	}

	// A predicate that simply did not match still counts as processed, exactly as
	// it did when this was a fall-through rather than a return.
	if !shouldAlert {
		return true
	}

	// ruleState, not "state": the local would otherwise shadow the state
	// library package imported for the read tracker.
	ruleState := rule.State
	if eventType == utils.HTTPEventType { // TODO: Manage state evaluation in a better way (this is abuse of the state map, we need a better way to pass payloads from rules.)
		ruleState = rm.evaluateHTTPPayloadState(rule.State, enrichedEvent)
	}
	rm.metrics.ReportRuleAlert(rule.ID)
	message, uniqueID, err := rm.getUniqueIdAndMessage(evalContext, rule)
	if err != nil {
		logger.L().Error("RuleManager - failed to get unique ID and message", helpers.Error(err))
		return false
	}

	if shouldCooldown, _ := rm.ruleCooldown.ShouldCooldown(uniqueID, enrichedEvent.ContainerID, rule.ID); shouldCooldown {
		rm.metrics.ReportAlertSuppressed(rule.ID, "cooldown")
		return false
	}

	// Emit OTEL log after cooldown so suppressed alerts are not recorded.
	// Dedup key includes eventType to avoid collapsing distinct alert types.
	dedupKey := rule.ID + "|" + enrichedEvent.ContainerID + "|" + string(eventType)
	rm.alertLogDedupMu.Lock()
	alreadySeen := rm.alertLogDedup.Contains(dedupKey)
	if !alreadySeen {
		rm.alertLogDedup.Add(dedupKey, struct{}{})
	}
	rm.alertLogDedupMu.Unlock()
	if !alreadySeen {
		var image, containerName string
		if enrichable, ok := enrichedEvent.Event.(utils.EnrichEvent); ok {
			image = enrichable.GetContainerImage()
			containerName = enrichable.GetContainer()
		}
		alertCtx, alertSpan := otelsetup.Tracer().Start(rm.ctx, "rule.alert",
			trace.WithAttributes(
				attribute.String("rule.id", rule.ID),
				attribute.String("rule.name", rule.Name),
				attribute.String("k8s.namespace.name", namespace),
				attribute.String("k8s.pod.name", pod),
				attribute.String("container.id", enrichedEvent.ContainerID),
				attribute.String("event.type", string(eventType)),
			))
		otelsetup.EmitAlertLogRecord(alertCtx, otelsetup.AlertLogAttrs{
			RuleID:        rule.ID,
			AlertType:     rule.Name,
			ContainerID:   enrichedEvent.ContainerID,
			ContainerName: containerName,
			Namespace:     namespace,
			PodName:       pod,
			Image:         image,
			EventType:     string(eventType),
		})
		alertSpan.End()
	}

	// The entries this rule's predicate actually read become the alert's
	// correlation evidence. Harvested here, after the predicate ran and after
	// cooldown, so a suppressed alert costs nothing.
	ruleFailure := rm.ruleFailureCreator.CreateRuleFailure(rule, enrichedEvent, rm.objectCache, message, uniqueID, apChecksum, ruleState, a.tracker.Hits())
	if ruleFailure == nil {
		logger.L().Error("RuleManager - failed to create rule failure", helpers.String("rule", rule.Name),
			helpers.String("message", message),
			helpers.String("uniqueID", uniqueID),
			helpers.String("enrichedEvent.EventType", string(eventType)),
		)
		return false
	}

	ruleFailure.SetWorkloadDetails(a.details)
	rm.exporter.SendRuleAlert(ruleFailure)
	return true
}

func (rm *RuleManager) enrichEventWithContext(enrichedEvent *events.EnrichedEvent) {
	// Extract mount namespace ID from the event
	mntnsID := uint64(0)
	if enrichEvent, ok := enrichedEvent.Event.(utils.EnrichEvent); ok {
		mntnsID = enrichEvent.GetMountNsID()
	}
	enrichedEvent.MountNamespaceID = mntnsID

	if mntnsID == 0 {
		return
	}
	if contextInfo, found := rm.mntnsRegistry.Lookup(mntnsID); found {
		enrichedEvent.SourceContext = contextInfo
		if logger.L().GetLevel() == helpers.DebugLevel.String() {
			logger.L().Debug("RuleManager - enriched event with context",
				helpers.String("mntns", strconv.FormatUint(mntnsID, 10)),
				helpers.String("context", string(contextInfo.Context())))
		}
	}
}

func (rm *RuleManager) isMonitoringEnabledForContext(sourceContext contextdetection.ContextInfo) bool {
	if sourceContext == nil {
		// No context information, default to Kubernetes (backward compatible)
		return true
	}

	contextType := sourceContext.Context()
	switch contextType {
	case contextdetection.Host:
		return rm.cfg.HostMonitoringEnabled
	case contextdetection.Standalone:
		return rm.cfg.StandaloneMonitoringEnabled
	case contextdetection.Kubernetes:
		// Kubernetes monitoring is always enabled (backward compatible)
		return true
	default:
		return true
	}
}

func (rm *RuleManager) HasApplicableRuleBindings(namespace, name string) bool {
	return len(rm.ruleBindingCache.ListRulesForPod(namespace, name)) > 0
}

func (rm *RuleManager) HasFinalApplicationProfile(pod *corev1.Pod) bool {
	for _, c := range utils.GetContainerStatuses(pod.Status) {
		state := rm.objectCache.ContainerProfileCache().GetContainerProfileState(utils.TrimRuntimePrefix(c.ContainerID))
		if state != nil && state.Error == nil {
			return state.Status == helpersv1.Completed && state.Completion == helpersv1.Full
		}
	}
	return false
}

func (rm *RuleManager) IsContainerMonitored(k8sContainerID string) bool {
	return rm.trackedContainers.Contains(k8sContainerID)
}

func (rm *RuleManager) IsPodMonitored(namespace, pod string) bool {
	return rm.podToWlid.Has(utils.CreateK8sPodID(namespace, pod))
}

func (rm *RuleManager) EvaluatePolicyRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string {
	results := []string{}

	creator := rm.ruleBindingCache.GetRuleCreator()
	rules := creator.CreateRulePolicyRulesByEventType(eventType)

	enrichedEvent := &events.EnrichedEvent{Event: event}
	var evalContext map[string]any

	for _, rule := range rules {
		if !rule.SupportPolicy {
			continue
		}

		ruleExpressions := rm.getRuleExpressions(rule, eventType)
		if len(ruleExpressions) == 0 {
			continue
		}

		if evalContext == nil {
			evalContext = rm.celEvaluator.CreateEvalContext(enrichedEvent)
		}

		startTime := time.Now()
		var shouldAlert bool
		var err error
		pprof.Do(context.Background(), pprof.Labels("rule", rule.ID), func(_ context.Context) {
			shouldAlert, err = rm.celEvaluator.EvaluateRuleWithContext(evalContext, eventType, ruleExpressions)
		})
		evaluationTime := time.Since(startTime)
		rm.metrics.ReportRuleEvaluationTime(rm.ctx, rule.ID, eventType, evaluationTime)

		if err != nil {
			logger.L().Ctx(rm.ctx).Error("RuleManager.EvaluatePolicyRulesForEvent - failed to evaluate rule", helpers.Error(err), helpers.String("rule", rule.ID), helpers.String("eventType", string(eventType)))
			continue
		}

		if shouldAlert {
			results = append(results, rule.ID)
		}
	}

	return results
}

func (rm *RuleManager) validateRulePolicy(rule typesv1.Rule, event utils.K8sEvent, containerID string) bool {
	cp, _, err := profilehelper.GetProjectedContainerProfile(rm.objectCache, containerID)
	if err != nil {
		return false
	}

	allowed, err := rm.rulePolicyValidator.Validate(rule.ID, event.(utils.EnrichEvent).GetComm(), cp)
	if err != nil {
		logger.L().Error("RuleManager - failed to validate rule policy", helpers.Error(err))
		return false
	}

	return allowed
}

func (rm *RuleManager) getRuleExpressions(rule typesv1.Rule, eventType utils.EventType) []typesv1.RuleExpression {
	var ruleExpressions []typesv1.RuleExpression
	for _, expression := range rule.Expressions.RuleExpression {
		if string(expression.EventType) == string(eventType) {
			ruleExpressions = append(ruleExpressions, expression)
		}
	}
	return ruleExpressions
}

// getUniqueIdAndMessage renders the alert's message and uniqueId.
//
// It takes the predicate's evalContext rather than rebuilding one. That matters
// for two reasons: state.get() in a message must resolve against the SAME entries
// the predicate matched, and uniqueId can then be derived from the join key --
// which is what lets rulecooldown collapse both legs of a bidirectional rule into
// a single alert instead of emitting one per leg.
func (rm *RuleManager) getUniqueIdAndMessage(evalContext map[string]any, rule typesv1.Rule) (string, string, error) {
	message, msgErr := rm.celEvaluator.EvaluateStringExpressionWithContext(evalContext, rule.Expressions.Message)
	if msgErr != nil {
		logger.L().Ctx(rm.ctx).Error("RuleManager - failed to evaluate message", helpers.Error(msgErr))
	}
	uniqueID, idErr := rm.celEvaluator.EvaluateStringExpressionWithContext(evalContext, rule.Expressions.UniqueID)
	if idErr != nil {
		logger.L().Ctx(rm.ctx).Error("RuleManager - failed to evaluate unique ID", helpers.Error(idErr))
	}

	uniqueID = hashStringToMD5(uniqueID)

	// Only the uniqueId error is returned, and the caller drops the alert on it.
	// That asymmetry is deliberate: uniqueId drives cooldown and backend dedup, so
	// a wrong one corrupts grouping, whereas a failed message costs description
	// only. Dropping a real detection because its text did not render would be the
	// worse failure, so a message error is logged and the alert still ships.
	return message, uniqueID, idErr
}

func isSupportedEventType(rules []typesv1.Rule, enrichedEvent *events.EnrichedEvent) bool {
	eventType := enrichedEvent.Event.GetEventType()
	for _, rule := range rules {
		for _, expression := range rule.Expressions.RuleExpression {
			if string(expression.EventType) == string(eventType) {
				return true
			}
		}
		// A write leg needs no ruleExpression for its event type -- that is what
		// makes write-without-alerting possible. Without this, write-only legs are
		// dropped before reaching the loop and the chain never forms.
		//
		// The string() casts are load-bearing: StateWrites carries
		// armotypes.EventType while eventType is utils.EventType. They are the same
		// strings, but not the same Go type.
		for _, w := range rule.StateWrites {
			if string(w.EventType) == string(eventType) {
				return true
			}
		}
	}
	return false
}

func hashStringToMD5(str string) string {
	hash := md5.Sum([]byte(str))
	hashString := fmt.Sprintf("%x", hash)
	return hashString
}

func (rm *RuleManager) evaluateHTTPPayloadState(state map[string]any, enrichedEvent *events.EnrichedEvent) map[string]any {
	payloadExpression, ok := state["payload"].(string)
	if !ok || payloadExpression == "" {
		return state
	}

	payloadValue, err := rm.celEvaluator.EvaluateExpression(enrichedEvent, payloadExpression)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate http payload expression", helpers.Error(err))
		return state
	}

	stateCopy := cloneState(state)
	stateCopy["payload"] = payloadValue

	return stateCopy
}

// extractEventFields extracts pre-filterable fields from an event.
// Called lazily on first rule with a prefilter — the returned value type is
// reused across all remaining rules.
func extractEventFields(event utils.K8sEvent) prefilter.EventFields {
	f := prefilter.EventFields{Extracted: true}

	switch event.GetEventType() {
	case utils.OpenEventType:
		if e, ok := event.(utils.OpenEvent); ok {
			f.Path = e.GetPath()
		}
	case utils.ExecveEventType:
		if e, ok := event.(utils.ExecEvent); ok {
			f.Path = e.GetExePath()
			f.ParentExePath = e.GetParentExePath()
			f.Comm = e.GetComm()
			f.Pcomm = e.GetPcomm()
		}
	case utils.HTTPEventType:
		if e, ok := event.(utils.HttpEvent); ok {
			f.SetDirection(string(e.GetDirection()))
			f.DstPort = e.GetDstPort()
			if req := e.GetRequest(); req != nil {
				f.SetMethod(req.Method)
			}
		}
	case utils.NetworkEventType:
		if e, ok := event.(utils.NetworkEvent); ok {
			f.DstPort = e.GetDstPort()
			f.PortEligible = true
		}
	case utils.SSHEventType:
		if e, ok := event.(utils.SshEvent); ok {
			f.DstPort = e.GetDstPort()
			f.PortEligible = true
		}
	}

	return f
}

func cloneState(state map[string]any) map[string]any {
	if state == nil {
		return map[string]any{}
	}

	stateCopy := make(map[string]any, len(state))
	for k, v := range state {
		stateCopy[k] = v
	}

	return stateCopy
}
