package rulemanager

import (
	"context"
	"errors"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/rulemanager"
	"node-agent/pkg/rulemanager/exporters"
	"node-agent/pkg/utils"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"

	bindingcache "node-agent/pkg/rulebindingmanager"

	"node-agent/pkg/metricsmanager"
	"node-agent/pkg/objectcache"

	tracerrandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"
	ruleenginetypes "node-agent/pkg/ruleengine/types"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	storageUtils "github.com/kubescape/storage/pkg/utils"
)

type RuleManager struct {
	cfg                      config.Config
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]    // key is k8sContainerID
	trackedContainers        mapset.Set[string]               // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error] // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	ruleBindingCache         bindingcache.RuleBindingCache
	objectCache              objectcache.ObjectCache
	exporter                 exporters.Exporter
	metrics                  metricsmanager.MetricsManager
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	preRunningContainerIDs   mapset.Set[string]
}

var _ rulemanager.RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, ruleBindingCache bindingcache.RuleBindingCache, objectCache objectcache.ObjectCache, exporter exporters.Exporter, metrics metricsmanager.MetricsManager, preRunningContainersIDs mapset.Set[string]) (*RuleManager, error) {
	return &RuleManager{
		cfg:                    cfg,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		containerMutexes:       storageUtils.NewMapMutex[string](),
		trackedContainers:      mapset.NewSet[string](),
		ruleBindingCache:       ruleBindingCache,
		objectCache:            objectCache,
		exporter:               exporter,
		metrics:                metrics,
		preRunningContainerIDs: preRunningContainersIDs,
	}, nil
}

func (rm *RuleManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	syscallTicker := time.NewTicker(5 * time.Second)
	var pod *corev1.Pod
	if err := backoff.Retry(func() error {
		p, err := rm.k8sClient.GetKubernetesClient().CoreV1().Pods(container.K8s.Namespace).Get(ctx, container.K8s.PodName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		pod = p
		return nil
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Ctx(ctx).Error("RuleManager - failed to get pod", helpers.Error(err),
			helpers.String("namespace", container.K8s.Namespace),
			helpers.String("name", container.K8s.PodName))
	}

	for {
		select {
		case <-syscallTicker.C:
			syscalls, err := rm.syscallPeekFunc(watchedContainer.NsMntId)
			if err != nil {
				logger.L().Ctx(ctx).Error("RuleManager - failed to get syscalls", helpers.Error(err),
					helpers.String("container ID", watchedContainer.ContainerID),
					helpers.String("k8s workload", watchedContainer.K8sContainerID))
				return err
			}

			rules := rm.ruleBindingCache.ListRulesForPod(pod.GetNamespace(), pod.GetName())
			for _, syscall := range syscalls {
				event := ruleenginetypes.SyscallEvent{
					Event: eventtypes.Event{
						Timestamp: eventtypes.Time(time.Now().UnixNano()),
						Type:      eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: watchedContainer.ContainerID,
								RuntimeName: container.Runtime.RuntimeName,
							},
							K8s: eventtypes.K8sMetadata{
								Node: pod.Spec.NodeName,
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									Namespace:     pod.GetNamespace(),
									PodName:       pod.GetName(),
									PodLabels:     pod.GetLabels(),
									ContainerName: watchedContainer.InstanceID.GetContainerName(),
								},
								HostNetwork: pod.Spec.HostNetwork,
							},
						},
					},
					WithMountNsID: eventtypes.WithMountNsID{
						MountNsID: watchedContainer.NsMntId,
					},
					Pid:         container.Pid,
					Uid:         container.OciConfig.Process.User.UID,
					Gid:         container.OciConfig.Process.User.GID,
					Comm:        container.OciConfig.Process.Args[0],
					SyscallName: syscall,
				}

				rm.processEvent(utils.SyscallEventType, &event, rules)
			}
		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				return nil
			}
		}
	}
}

func (rm *RuleManager) startRuleManager(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "RuleManager.startRuleManager")
	defer span.End()

	syncChannel := make(chan error, 10)
	rm.watchedContainerChannels.Set(container.Runtime.ContainerID, syncChannel)

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:    container.Runtime.ContainerID,
		SyncChannel:    syncChannel,
		K8sContainerID: k8sContainerID,
		NsMntId:        container.Mntns,
	}

	if err := rm.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Info("ApplicationProfileManager - stop monitor on container", helpers.String("reason", err.Error()),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	rm.deleteResources(watchedContainer)
}

func (rm *RuleManager) deleteResources(watchedContainer *utils.WatchedContainerData) {
	// make sure we don't run deleteResources and saveProfile at the same time
	rm.containerMutexes.Lock(watchedContainer.K8sContainerID)
	defer rm.containerMutexes.Unlock(watchedContainer.K8sContainerID)

	// delete resources
	watchedContainer.UpdateDataTicker.Stop()
	rm.trackedContainers.Remove(watchedContainer.K8sContainerID)
	rm.watchedContainerChannels.Delete(watchedContainer.ContainerID)

	// clean cached k8s podSpec
	// clean cached rules
}

// This function is not used in the current implementation (Might be used in the future).
// func (rm *RuleManager) waitForContainer(k8sContainerID string) error {
// 	return backoff.Retry(func() error {
// 		if rm.trackedContainers.Contains(k8sContainerID) {
// 			return nil
// 		}
// 		return fmt.Errorf("container %s not found", k8sContainerID)
// 	}, backoff.NewExponentialBackOff())
// }

func (rm *RuleManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if rm.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}
		rm.trackedContainers.Add(k8sContainerID)
		go rm.startRuleManager(rm.ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		channel := rm.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		rm.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (rm *RuleManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	rm.syscallPeekFunc = peek
}

func (rm *RuleManager) ReportCapability(k8sContainerID string, event tracercapabilitiestype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportCapability event")
		return
	}
	// list capability rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.CapabilitiesEventType, &event, rules)
}

func (rm *RuleManager) ReportFileExec(k8sContainerID string, event tracerexectype.Event) {
	// TODO: Do we need to wait for this?
	// if err := rm.waitForContainer(k8sContainerID); err != nil {
	// 	return
	// }
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportFileExec event")
		return
	}
	// list exec rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.ExecveEventType, &event, rules)
}

func (rm *RuleManager) ReportFileOpen(k8sContainerID string, event traceropentype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportFileOpen event")
		return
	}
	// list open rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.OpenEventType, &event, rules)

}
func (rm *RuleManager) ReportNetworkEvent(k8sContainerID string, event tracernetworktype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportNetworkEvent event")
		return
	}
	// list network rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.NetworkEventType, &event, rules)
}

func (rm *RuleManager) ReportDNSEvent(event tracerdnstype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportDNSEvent event")
		return
	}
	// list dns rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.DnsEventType, &event, rules)
}

func (rm *RuleManager) ReportRandomxEvent(k8sContainerID string, event tracerrandomxtype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from randomx event")
		return
	}

	// list randomx rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.RandomXEventType, &event, rules)
}

func (rm *RuleManager) processEvent(eventType utils.EventType, event interface{}, rules []ruleengine.RuleEvaluator) {

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if !isEventRelevant(rule.Requirements(), eventType) {
			continue
		}

		res := rule.ProcessEvent(eventType, event, rm.objectCache)
		if res != nil {
			logger.L().Info("RuleManager FAILED - rule alert", helpers.String("rule", rule.Name()))
			rm.exporter.SendRuleAlert(res)
			rm.metrics.ReportRuleAlert(rule.Name())
		}
		rm.metrics.ReportRuleProcessed(rule.Name())
	}
}

// Checks if the event type is relevant to the rule.
func isEventRelevant(ruleSpec ruleengine.RuleSpec, eventType utils.EventType) bool {
	for _, i := range ruleSpec.RequiredEventTypes() {
		if i == eventType {
			return true
		}
	}
	return false
}
