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
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters/adapters"
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
	syscallPeekFunc      func(nsMountId uint64) ([]string, error)
	podToWlid            maps.SafeMap[string, string] // key is namespace/podName
	containerIdToShimPid maps.SafeMap[string, uint32]
	containerIdToPid     maps.SafeMap[string, uint32]
	enricher             types.Enricher
	processManager       processtree.ProcessTreeManager
	celEvaluator         cel.CELRuleEvaluator
	ruleCooldown         *rulecooldown.RuleCooldown
	adapterFactory       *ruleadapters.EventRuleAdapterFactory
	ruleFailureCreator   ruleadapters.RuleFailureCreatorInterface
	rulePolicyValidator  *RulePolicyValidator
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
	celEvaluator cel.CELRuleEvaluator,
) (*RuleManager, error) {
	ruleFailureCreator := ruleadapters.NewRuleFailureCreator(enricher, dnsManager, adapterFactory)
	rulePolicyValidator := NewRulePolicyValidator(objectCache)

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

func (rm *RuleManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	rm.syscallPeekFunc = peek
}

func (rm *RuleManager) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
	var profileExists bool
	podId := utils.CreateK8sPodID(enrichedEvent.Event.GetNamespace(), enrichedEvent.Event.GetPod())
	details, ok := rm.podToWlid.Load(podId)
	if !ok {
		return
	}

	if enrichedEvent.Event.GetPod() == "" || enrichedEvent.Event.GetNamespace() == "" {
		return
	}

	rules := rm.ruleBindingCache.ListRulesForPod(enrichedEvent.Event.GetNamespace(), enrichedEvent.Event.GetPod())
	if len(rules) == 0 {
		return
	}

	if !isSupportedEventType(rules, enrichedEvent) {
		return
	}

	_, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, enrichedEvent.ContainerID)
	profileExists = err == nil

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !profileExists && rule.ProfileDependency == armotypes.Required {
			continue
		}

		ruleExpressions := rm.getRuleExpressions(rule, enrichedEvent.EventType)
		if len(ruleExpressions) == 0 {
			continue
		}

		if rule.SupportPolicy && rm.validateRulePolicy(rule, enrichedEvent.Event, enrichedEvent.ContainerID) {
			continue
		}

		startTime := time.Now()
		shouldAlert, err := rm.evaluateRule(enrichedEvent, enrichedEvent.EventType, rule)
		evaluationTime := time.Since(startTime)
		rm.metrics.ReportRuleEvaluationTime(rule.Name, enrichedEvent.EventType, evaluationTime)

		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate rule", helpers.Error(err))
			continue
		}

		if shouldAlert {
			rm.metrics.ReportRuleAlert(rule.Name)
			message, uniqueID, err := rm.getUniqueIdAndMessage(enrichedEvent, rule)
			if err != nil {
				logger.L().Error("RuleManager - failed to get unique ID and message", helpers.Error(err))
				continue
			}

			if shouldCooldown, _ := rm.ruleCooldown.ShouldCooldown(uniqueID, enrichedEvent.ContainerID, rule.ID); shouldCooldown {
				continue
			}

			ruleFailure := rm.ruleFailureCreator.CreateRuleFailure(rule, enrichedEvent, rm.objectCache, message, uniqueID)
			if ruleFailure == nil {
				logger.L().Error("RuleManager - failed to create rule failure", helpers.String("rule", rule.Name),
					helpers.String("message", message),
					helpers.String("uniqueID", uniqueID),
					helpers.String("enrichedEvent.EventType", string(enrichedEvent.EventType)),
				)
				continue
			}

			ruleFailure.SetWorkloadDetails(details)
			rm.exporter.SendRuleAlert(ruleFailure)
		}
		rm.metrics.ReportRuleProcessed(rule.Name)
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
	results := []string{}

	creator := rm.ruleBindingCache.GetRuleCreator()
	rules := creator.CreateRulePolicyRulesByEventType(eventType)

	for _, rule := range rules {
		if !rule.SupportPolicy {
			continue
		}

		enrichedEvent := &events.EnrichedEvent{
			//Event: event,
			EventType: eventType}
		ruleExpressions := rm.getRuleExpressions(rule, eventType)
		if len(ruleExpressions) == 0 {
			continue
		}

		startTime := time.Now()
		shouldAlert, err := rm.celEvaluator.EvaluateRule(enrichedEvent, ruleExpressions)
		evaluationTime := time.Since(startTime)
		rm.metrics.ReportRuleEvaluationTime(rule.ID, eventType, evaluationTime)

		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate rule", helpers.Error(err))
			continue
		}

		if shouldAlert {
			results = append(results, rule.ID)
		}
	}

	return results
}

func (rm *RuleManager) evaluateRule(enrichedEvent *events.EnrichedEvent, eventType utils.EventType, rule typesv1.Rule) (bool, error) {
	// Special event types are evaluated by map because we're doing parsing optimizations
	// TODO: Manage special event types in a better way
	if eventType == utils.HTTPEventType {
		eventAdapter, ok := rm.adapterFactory.GetAdapter(enrichedEvent.EventType)
		if !ok {
			logger.L().Error("RuleManager - no adapter registered for event type", helpers.String("eventType", string(enrichedEvent.EventType)))
			return false, nil
		}

		eventMap := eventAdapter.ToMap(enrichedEvent)
		defer adapters.ReleaseEventMap(eventMap)

		shouldAlert, err := rm.celEvaluator.EvaluateRuleByMap(eventMap, eventType, rule.Expressions.RuleExpression)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate rule", helpers.Error(err))
			return false, err
		}
		return shouldAlert, nil
	} else {
		shouldAlert, err := rm.celEvaluator.EvaluateRule(enrichedEvent, rule.Expressions.RuleExpression)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate rule", helpers.Error(err))
			return false, err
		}
		return shouldAlert, nil
	}
}

func (rm *RuleManager) validateRulePolicy(rule typesv1.Rule, event utils.K8sEvent, containerID string) bool {
	ap, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, containerID)
	if err != nil {
		return false
	}

	allowed, err := rm.rulePolicyValidator.Validate(rule.ID, utils.GetCommFromEvent(event), &ap)
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

func (rm *RuleManager) getUniqueIdAndMessage(enrichedEvent *events.EnrichedEvent, rule typesv1.Rule) (string, string, error) {
	// Special event types are evaluated by map because we're doing parsing optimizations
	// TODO: Manage special event types in a better way
	if enrichedEvent.EventType == utils.HTTPEventType {
		eventAdapter, ok := rm.adapterFactory.GetAdapter(enrichedEvent.EventType)
		if !ok {
			logger.L().Error("RuleManager - no adapter registered for event type", helpers.String("eventType", string(enrichedEvent.EventType)))
			return "", "", nil
		}
		eventMap := eventAdapter.ToMap(enrichedEvent)
		defer adapters.ReleaseEventMap(eventMap)

		message, err := rm.celEvaluator.EvaluateExpressionByMap(eventMap, rule.Expressions.Message, enrichedEvent.EventType)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate message", helpers.Error(err))
		}
		uniqueID, err := rm.celEvaluator.EvaluateExpressionByMap(eventMap, rule.Expressions.UniqueID, enrichedEvent.EventType)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate unique ID", helpers.Error(err))
		}
		uniqueID = hashStringToMD5(uniqueID)
		return message, uniqueID, err
	} else {
		message, err := rm.celEvaluator.EvaluateExpression(enrichedEvent, rule.Expressions.Message)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate message", helpers.Error(err))
		}
		uniqueID, err := rm.celEvaluator.EvaluateExpression(enrichedEvent, rule.Expressions.UniqueID)
		if err != nil {
			logger.L().Error("RuleManager - failed to evaluate unique ID", helpers.Error(err))
		}

		uniqueID = hashStringToMD5(uniqueID)

		return message, uniqueID, err
	}
}

func isSupportedEventType(rules []typesv1.Rule, enrichedEvent *events.EnrichedEvent) bool {
	for _, rule := range rules {
		for _, expression := range rule.Expressions.RuleExpression {
			if string(expression.EventType) == string(enrichedEvent.EventType) {
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
