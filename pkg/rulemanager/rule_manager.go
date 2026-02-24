package rulemanager

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
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
	"github.com/kubescape/node-agent/pkg/processtree"
	bindingcache "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	corev1 "k8s.io/api/core/v1"
)

const (
	syscallPeriod = 5 * time.Second
)

type RuleManager struct {
	cfg                  config.Config
	ruleBindingCache     bindingcache.RuleBindingCache
	trackedContainers    mapset.Set[string] // key is k8sContainerID
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
) (*RuleManager, error) {
	ruleFailureCreator := ruleadapters.NewRuleFailureCreator(enricher, dnsManager, adapterFactory)
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
		ruleFailureCreator:  ruleFailureCreator,
		rulePolicyValidator: rulePolicyValidator,
		mntnsRegistry:       mntnsRegistry,
		detectorManager:     detectorManager,
	}

	return r, nil
}

func (rm *RuleManager) startRuleManager(container *containercollection.Container, k8sContainerID string) {
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

	if err := rm.monitorContainer(container, k8sContainerID); err != nil {
		logger.L().Debug("RuleManager - stop monitor on container", helpers.String("reason", err.Error()),
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s container id", k8sContainerID))
	}
}

func (rm *RuleManager) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
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
		// TODO: rule filtering based on context
		rules = rm.ruleBindingCache.GetRuleCreator().CreateAllRules()
	}

	if len(rules) == 0 {
		return
	}

	eventType := enrichedEvent.Event.GetEventType()

	_, apChecksum, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, enrichedEvent.ContainerID)
	profileExists = err == nil

	// Early exit if monitoring is disabled for this context - skip rule evaluation
	if !rm.isMonitoringEnabledForContext(enrichedEvent.SourceContext) {
		return
	}

	evalContext := rm.celEvaluator.CreateEvalContext(enrichedEvent.Event)
	defer evalContext.Release()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Fast path: skip rules that have no expressions for this event type
		ruleExpressions := rule.ExpressionsByEventType[eventType]
		if len(ruleExpressions) == 0 {
			continue
		}

		if !RuleAppliesToContext(&rule, enrichedEvent.SourceContext) {
			continue
		}
		// Skip profile dependency checks for non-K8s contexts (profiles are K8s-specific)
		// Only K8s contexts should enforce profile dependencies
		if isK8sContext && !profileExists && rule.ProfileDependency == armotypes.Required {
			continue
		}

		if rule.SupportPolicy && rm.validateRulePolicy(rule, enrichedEvent.Event, enrichedEvent.ContainerID) {
			continue
		}

		startTime := time.Now()
		shouldAlert, err := rm.celEvaluator.EvaluateRuleWithContext(evalContext, ruleExpressions)
		evaluationTime := time.Since(startTime)
		rm.metrics.ReportRuleEvaluationTime(rule.Name, eventType, evaluationTime)

		if err != nil {
			logger.L().Error("RuleManager.ReportEnrichedEvent - failed to evaluate rule", helpers.Error(err), helpers.String("rule", rule.ID), helpers.String("eventType", string(eventType)))
			continue
		}

		if shouldAlert {
			state := rule.State
			if eventType == utils.HTTPEventType { // TODO: Manage state evaluation in a better way (this is abuse of the state map, we need a better way to pass payloads from rules.)
				state = rm.evaluateHTTPPayloadState(rule.State, evalContext)
			}
			rm.metrics.ReportRuleAlert(rule.Name)
			message, uniqueID, err := rm.getUniqueIdAndMessage(evalContext, rule)
			if err != nil {
				logger.L().Error("RuleManager - failed to get unique ID and message", helpers.Error(err))
				continue
			}

			if shouldCooldown, _ := rm.ruleCooldown.ShouldCooldown(uniqueID, enrichedEvent.ContainerID, rule.ID); shouldCooldown {
				continue
			}

			ruleFailure := rm.ruleFailureCreator.CreateRuleFailure(rule, enrichedEvent, rm.objectCache, message, uniqueID, apChecksum, state)
			if ruleFailure == nil {
				logger.L().Error("RuleManager - failed to create rule failure", helpers.String("rule", rule.Name),
					helpers.String("message", message),
					helpers.String("uniqueID", uniqueID),
					helpers.String("enrichedEvent.EventType", string(eventType)),
				)
				continue
			}

			ruleFailure.SetWorkloadDetails(details)
			rm.exporter.SendRuleAlert(ruleFailure)
		}
		rm.metrics.ReportRuleProcessed(rule.Name)
	}
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
		logger.L().Debug("RuleManager - enriched event with context",
			helpers.String("mntns", fmt.Sprintf("%d", mntnsID)),
			helpers.String("context", string(contextInfo.Context())))
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
		ap := rm.objectCache.ApplicationProfileCache().GetApplicationProfile(utils.TrimRuntimePrefix(c.ContainerID))
		if ap != nil {
			if status, ok := ap.Annotations[helpersv1.StatusMetadataKey]; ok {
				// in theory, only completed profiles are stored in cache, but we check anyway
				return status == helpersv1.Completed
			}
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
	var results []string

	creator := rm.ruleBindingCache.GetRuleCreator()
	rules := creator.CreateRulePolicyRulesByEventType(eventType)

	evalContext := rm.celEvaluator.CreateEvalContext(event)
	defer evalContext.Release()

	for _, rule := range rules {
		if !rule.SupportPolicy {
			continue
		}

		ruleExpressions := rule.ExpressionsByEventType[eventType]
		if len(ruleExpressions) == 0 {
			continue
		}

		startTime := time.Now()
		shouldAlert, err := rm.celEvaluator.EvaluateRuleWithContext(evalContext, ruleExpressions)
		evaluationTime := time.Since(startTime)
		rm.metrics.ReportRuleEvaluationTime(rule.ID, eventType, evaluationTime)

		if err != nil {
			logger.L().Error("RuleManager.EvaluatePolicyRulesForEvent - failed to evaluate rule", helpers.Error(err), helpers.String("rule", rule.ID), helpers.String("eventType", string(eventType)))
			continue
		}

		if shouldAlert {
			results = append(results, rule.ID)
		}
	}

	return results
}

func (rm *RuleManager) validateRulePolicy(rule typesv1.Rule, event utils.K8sEvent, containerID string) bool {
	ap, _, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, containerID)
	if err != nil {
		return false
	}

	allowed, err := rm.rulePolicyValidator.Validate(rule.ID, event.(utils.EnrichEvent).GetComm(), &ap)
	if err != nil {
		logger.L().Error("RuleManager - failed to validate rule policy", helpers.Error(err))
		return false
	}

	return allowed
}

func (rm *RuleManager) getUniqueIdAndMessage(evalContext *cel.EventActivation, rule typesv1.Rule) (string, string, error) {
	message, err := rm.celEvaluator.EvaluateExpressionWithContext(evalContext, rule.Expressions.Message)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate message", helpers.Error(err))
	}
	uniqueID, err := rm.celEvaluator.EvaluateExpressionWithContext(evalContext, rule.Expressions.UniqueID)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate unique ID", helpers.Error(err))
	}

	uniqueID = hashStringToMD5(uniqueID)

	return message, uniqueID, err
}

func hashStringToMD5(str string) string {
	hash := md5.Sum([]byte(str))
	hashString := fmt.Sprintf("%x", hash)
	return hashString
}

func (rm *RuleManager) evaluateHTTPPayloadState(state map[string]any, evalContext *cel.EventActivation) map[string]any {
	payloadExpression, ok := state["payload"].(string)
	if !ok || payloadExpression == "" {
		return state
	}

	payloadValue, err := rm.celEvaluator.EvaluateExpressionWithContext(evalContext, payloadExpression)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate http payload expression", helpers.Error(err))
		return state
	}

	stateCopy := cloneState(state)
	stateCopy["payload"] = payloadValue

	return stateCopy
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
