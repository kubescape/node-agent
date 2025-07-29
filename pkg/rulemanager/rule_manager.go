package rulemanager

import (
	"context"
	"encoding/json"
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
	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator/validators"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulefailurecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"

	cel "github.com/kubescape/node-agent/pkg/rulemanager/cel"
	corev1 "k8s.io/api/core/v1"
)

const (
	maxFileSize   = 50 * 1024 * 1024 // 50MB
	syscallPeriod = 5 * time.Second
)

type RuleManager struct {
	cfg                     config.Config
	ruleBindingCache        bindingcache.RuleBindingCache
	trackedContainers       mapset.Set[string] // key is k8sContainerID
	k8sClient               k8sclient.K8sClientInterface
	ctx                     context.Context
	objectCache             objectcache.ObjectCache
	exporter                exporters.Exporter
	metrics                 metricsmanager.MetricsManager
	syscallPeekFunc         func(nsMountId uint64) ([]string, error)
	podToWlid               maps.SafeMap[string, string] // key is namespace/podName
	nodeName                string
	clusterName             string
	containerIdToShimPid    maps.SafeMap[string, uint32]
	containerIdToPid        maps.SafeMap[string, uint32]
	enricher                ruleenginetypes.Enricher
	processManager          processtree.ProcessTreeManager
	ruleCooldown            *rulecooldown.RuleCooldown
	CelEvaluator            cel.CELRuleEvaluator
	profileValidatorFactory profilevalidator.ProfileValidatorFactory
	registry                profilevalidator.ProfileRegistry
	ruleFailureCreator      rulefailurecreator.RuleFailureCreatorInterface
}

var _ RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, ruleBindingCache bindingcache.RuleBindingCache, objectCache objectcache.ObjectCache, exporter exporters.Exporter, metrics metricsmanager.MetricsManager, nodeName string, clusterName string, processManager processtree.ProcessTreeManager, dnsManager dnsmanager.DNSResolver, enricher ruleenginetypes.Enricher, ruleCooldown *rulecooldown.RuleCooldown) (*RuleManager, error) {
	profileValidatorFactory := profilevalidator.NewProfileValidatorFactory(objectCache)
	registry := profilevalidator.NewProfileRegistry(objectCache)
	ruleFailureCreator := rulefailurecreator.NewRuleFailureCreator(enricher, dnsManager)

	validators.RegisterAllValidators(profileValidatorFactory, objectCache)

	r := &RuleManager{
		cfg:                     cfg,
		ctx:                     ctx,
		k8sClient:               k8sClient,
		trackedContainers:       mapset.NewSet[string](),
		ruleBindingCache:        ruleBindingCache,
		objectCache:             objectCache,
		exporter:                exporter,
		metrics:                 metrics,
		nodeName:                nodeName,
		clusterName:             clusterName,
		enricher:                enricher,
		processManager:          processManager,
		ruleCooldown:            ruleCooldown,
		profileValidatorFactory: profileValidatorFactory,
		registry:                registry,
		ruleFailureCreator:      ruleFailureCreator,
	}

	ruleFailureCreator.SetContainerIdToPid(&r.containerIdToPid)
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
	eventProfile := rm.getProfileChecks(enrichedEvent)

	rules := rm.ruleBindingCache.ListRulesForPod(enrichedEvent.Event.GetNamespace(), enrichedEvent.Event.GetPod())

	for _, rule := range rules {
		if rule.Enabled {
			if rule.ProfileDependency == armotypes.Required {
				if len(eventProfile) == 0 {
					logger.L().Debug("RuleManager - profile dependency not met", helpers.String("rule", rule.Name))
					continue
				}
			}

			serializedEvent, err := rm.serializeEvent(enrichedEvent, eventProfile)
			if err != nil {
				continue
			}

			ruleExpressions := rm.getRuleExpressions(rule, enrichedEvent)

			shouldAlert, err := rm.CelEvaluator.EvaluateRule(serializedEvent, ruleExpressions)
			if err != nil {
				logger.L().Error("RuleManager - failed to evaluate rule", helpers.Error(err))
				continue
			}

			if shouldAlert {
				rm.metrics.ReportRuleAlert(rule.Name)
				message, uniqueID, err := rm.getUniqueIdAndMessage(serializedEvent, rule)
				if err != nil {
					logger.L().Error("RuleManager - failed to get unique ID and message", helpers.Error(err))
					continue
				}

				ruleFailure := rm.ruleFailureCreator.CreateRuleFailure(rule, enrichedEvent, rm.objectCache, message, uniqueID)
				if shouldCooldown, count := rm.ruleCooldown.ShouldCooldown(ruleFailure); shouldCooldown {
					logger.L().Debug("RuleManager - rule cooldown", helpers.String("rule", rule.Name), helpers.Int("count", count))
					continue
				}

				rm.exporter.SendRuleAlert(ruleFailure)
			}

			rm.metrics.ReportRuleProcessed(rule.Name)
		}
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

		results = append(results, rule.ID)
	}

	return results
}

func (rm *RuleManager) getProfileChecks(enrichedEvent *events.EnrichedEvent) map[string]bool {
	eventProfile := map[string]bool{}

	ap, nn, ok := rm.registry.GetAvailableProfiles("enrichedEvent.ContainerName", enrichedEvent.ContainerID)
	if ok {
		profileValidator := rm.profileValidatorFactory.GetProfileValidator(enrichedEvent.EventType)
		results, err := profileValidator.ValidateProfile(enrichedEvent.Event, ap, nn)
		if err != nil {
			logger.L().Error("RuleManager - failed to validate profile", helpers.Error(err))
		}
		eventProfile = results.GetChecksAsMap()
	}

	return eventProfile
}

func (rm *RuleManager) serializeEvent(enrichedEvent *events.EnrichedEvent, eventProfile map[string]bool) ([]byte, error) {
	eventWithChecks := map[string]interface{}{
		"event":  enrichedEvent.Event,
		"checks": eventProfile,
	}

	serializedEvent, err := json.Marshal(eventWithChecks)
	if err != nil {
		logger.L().Error("RuleManager - failed to marshal event", helpers.Error(err))
		return nil, err
	}

	return serializedEvent, nil
}

func (rm *RuleManager) getRuleExpressions(rule typesv1.RuleSpec, enrichedEvent *events.EnrichedEvent) []typesv1.RuleExpression {
	var ruleExpressions []typesv1.RuleExpression
	for _, expression := range rule.Expressions.RuleExpression {
		if expression.EventType == enrichedEvent.EventType {
			ruleExpressions = append(ruleExpressions, expression)
		}
	}
	return ruleExpressions
}

func (rm *RuleManager) getUniqueIdAndMessage(serializedEvent []byte, rule typesv1.RuleSpec) (string, string, error) {
	message, err := rm.CelEvaluator.EvaluateExpression(serializedEvent, rule.Expressions.Message)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate message", helpers.Error(err))
	}
	uniqueID, err := rm.CelEvaluator.EvaluateExpression(serializedEvent, rule.Expressions.UniqueID)
	if err != nil {
		logger.L().Error("RuleManager - failed to evaluate unique ID", helpers.Error(err))
	}

	return message, uniqueID, err
}
