package rulemanager

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dustin/go-humanize"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processmanager"
	bindingcache "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

const (
	maxFileSize   = 50 * 1024 * 1024 // 50MB
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
	nodeName             string
	clusterName          string
	containerIdToShimPid maps.SafeMap[string, uint32]
	containerIdToPid     maps.SafeMap[string, uint32]
	enricher             ruleenginetypes.Enricher
	processManager       processmanager.ProcessManagerClient
	dnsManager           dnsmanager.DNSResolver
}

var _ rulemanager.RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, ruleBindingCache bindingcache.RuleBindingCache, objectCache objectcache.ObjectCache, exporter exporters.Exporter, metrics metricsmanager.MetricsManager, nodeName string, clusterName string, processManager processmanager.ProcessManagerClient, dnsManager dnsmanager.DNSResolver, enricher ruleenginetypes.Enricher) (*RuleManager, error) {
	return &RuleManager{
		cfg:               cfg,
		ctx:               ctx,
		k8sClient:         k8sClient,
		trackedContainers: mapset.NewSet[string](),
		ruleBindingCache:  ruleBindingCache,
		objectCache:       objectCache,
		exporter:          exporter,
		metrics:           metrics,
		nodeName:          nodeName,
		clusterName:       clusterName,
		enricher:          enricher,
		processManager:    processManager,
		dnsManager:        dnsManager,
	}, nil
}

func (rm *RuleManager) monitorContainer(container *containercollection.Container, k8sContainerID string) error {
	logger.L().Debug("RuleManager - start monitor on container",
		helpers.String("container ID", container.Runtime.ContainerID),
		helpers.String("k8s container id", k8sContainerID))

	syscallTicker := time.NewTicker(syscallPeriod)

	for {
		select {
		case <-rm.ctx.Done():
			logger.L().Debug("RuleManager - stop monitor on container",
				helpers.String("container ID", container.Runtime.ContainerID),
				helpers.String("k8s container id", k8sContainerID))
			return nil
		case <-syscallTicker.C:
			if rm.syscallPeekFunc == nil {
				logger.L().Debug("RuleManager - syscallPeekFunc is not set", helpers.String("container ID", container.Runtime.ContainerID))
				continue
			}

			if container.Mntns == 0 {
				logger.L().Debug("RuleManager - mount namespace ID is not set", helpers.String("container ID", container.Runtime.ContainerID))
			}

			if !rm.trackedContainers.Contains(k8sContainerID) {
				logger.L().Debug("RuleManager - container is not tracked", helpers.String("container ID", container.Runtime.ContainerID))
				return nil
			}

			var syscalls []string
			if syscallsFromFunc, err := rm.syscallPeekFunc(container.Mntns); err == nil {
				syscalls = syscallsFromFunc
			}

			if len(syscalls) == 0 {
				continue
			}

			rules := rm.ruleBindingCache.ListRulesForPod(container.K8s.Namespace, container.K8s.PodName)
			for _, syscall := range syscalls {
				event := ruleenginetypes.SyscallEvent{
					Event: eventtypes.Event{
						Timestamp: eventtypes.Time(time.Now().UnixNano()),
						Type:      eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: container.Runtime.ContainerID,
								RuntimeName: container.Runtime.RuntimeName,
							},
							K8s: eventtypes.K8sMetadata{
								Node: rm.nodeName,
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									Namespace:     container.K8s.Namespace,
									PodName:       container.K8s.PodName,
									PodLabels:     container.K8s.PodLabels,
									ContainerName: container.K8s.ContainerName,
								},
							},
						},
					},
					WithMountNsID: eventtypes.WithMountNsID{
						MountNsID: container.Mntns,
					},
					Pid: container.ContainerPid(),
					// TODO: Figure out how to get UID, GID and comm from the syscall.
					// Uid:         container.OciConfig.Process.User.UID,
					// Gid:         container.OciConfig.Process.User.GID,
					// Comm:        container.OciConfig.Process.Args[0],
					SyscallName: syscall,
				}

				rm.processEvent(utils.SyscallEventType, &event, rules)
			}
		}
	}
}

func (rm *RuleManager) startRuleManager(container *containercollection.Container, k8sContainerID string) {
	if err := rm.waitForSharedContainerData(container.Runtime.ContainerID); err != nil {
		logger.L().Error("RuleManager - failed to get shared container data", helpers.Error(err))
		return
	}

	podID := utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)
	if !rm.podToWlid.Has(podID) {
		w := rm.objectCache.K8sObjectCache().GetSharedContainerData(container.Runtime.ContainerID).Wlid
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

func (rm *RuleManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if rm.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if rm.trackedContainers.Contains(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("RuleManager - container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}

		rm.trackedContainers.Add(k8sContainerID)
		shim, err := utils.GetProcessStat(int(notif.Container.ContainerPid()))
		if err != nil {
			logger.L().Warning("RuleManager - failed to get shim process", helpers.Error(err))
		} else {
			rm.containerIdToShimPid.Set(notif.Container.Runtime.ContainerID, uint32(shim.PPID))
		}
		rm.containerIdToPid.Set(notif.Container.Runtime.ContainerID, notif.Container.ContainerPid())
		go rm.startRuleManager(notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		rm.trackedContainers.Remove(k8sContainerID)
		rm.podToWlid.Delete(utils.CreateK8sPodID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName))
		rm.containerIdToShimPid.Delete(notif.Container.Runtime.ContainerID)
		rm.containerIdToPid.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (rm *RuleManager) waitForSharedContainerData(containerID string) error {
	return backoff.Retry(func() error {
		if rm.objectCache.K8sObjectCache().GetSharedContainerData(containerID) != nil {
			return nil
		}
		return fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.NewExponentialBackOff())
}

func (rm *RuleManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	rm.syscallPeekFunc = peek
}

func (rm *RuleManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Warning("RuleManager - failed to get namespace and pod name from custom event")
		return
	}

	// list custom rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())
	rm.processEvent(eventType, event, rules)
}

func (rm *RuleManager) processEvent(eventType utils.EventType, event utils.K8sEvent, rules []ruleengine.RuleEvaluator) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}

		if !isEventRelevant(rule.Requirements(), eventType) {
			continue
		}

		res := rule.ProcessEvent(eventType, event, rm.objectCache)
		if res != nil {
			res = rm.enrichRuleFailure(res)
			res.SetWorkloadDetails(rm.podToWlid.Get(utils.CreateK8sPodID(res.GetRuntimeAlertK8sDetails().Namespace, res.GetRuntimeAlertK8sDetails().PodName)))
			rm.exporter.SendRuleAlert(res)

			rm.metrics.ReportRuleAlert(rule.Name())
		}
		rm.metrics.ReportRuleProcessed(rule.Name())
	}
}
func (rm *RuleManager) enrichRuleFailure(ruleFailure ruleengine.RuleFailure) ruleengine.RuleFailure {
	var err error
	var path string
	var hostPath string
	if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path == "" {
		path, err = utils.GetPathFromPid(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID)
	}

	if err != nil {
		if ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path != "" {
			hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", rm.containerIdToPid.Get(ruleFailure.GetTriggerEvent().Runtime.ContainerID), ruleFailure.GetRuntimeProcessDetails().ProcessTree.Path))
		}
	} else {
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID, path))
	}

	// Enrich BaseRuntimeAlert
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()

	baseRuntimeAlert.Timestamp = time.Unix(0, int64(ruleFailure.GetTriggerEvent().Timestamp))
	var size int64 = 0
	if hostPath != "" {
		size, err = utils.GetFileSize(hostPath)
		if err != nil {
			size = 0
		}
	}

	if baseRuntimeAlert.Size == "" && hostPath != "" && size != 0 {
		baseRuntimeAlert.Size = humanize.Bytes(uint64(size))
	}

	if size != 0 && size < maxFileSize && hostPath != "" {
		if baseRuntimeAlert.MD5Hash == "" || baseRuntimeAlert.SHA1Hash == "" {
			sha1hash, md5hash, err := utils.CalculateFileHashes(hostPath)
			if err == nil {
				baseRuntimeAlert.MD5Hash = md5hash
				baseRuntimeAlert.SHA1Hash = sha1hash
			}
		}
	}

	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := ruleFailure.GetRuntimeProcessDetails()

	err = backoff.Retry(func() error {
		tree, err := rm.processManager.GetProcessTreeForPID(
			ruleFailure.GetRuntimeProcessDetails().ContainerID,
			int(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID),
		)
		if err != nil {
			return err
		}
		runtimeProcessDetails.ProcessTree = tree
		return nil
	}, backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(50*time.Millisecond),
		backoff.WithMaxInterval(200*time.Millisecond),
		backoff.WithMaxElapsedTime(500*time.Millisecond),
	))

	if err != nil && rm.containerIdToShimPid.Has(ruleFailure.GetRuntimeProcessDetails().ContainerID) {
		logger.L().Debug("RuleManager - failed to get process tree, trying to get process tree from shim",
			helpers.Error(err),
			helpers.String("container ID", ruleFailure.GetRuntimeProcessDetails().ContainerID))

		if tree, err := utils.CreateProcessTree(&runtimeProcessDetails.ProcessTree,
			rm.containerIdToShimPid.Get(ruleFailure.GetRuntimeProcessDetails().ContainerID)); err == nil {
			runtimeProcessDetails.ProcessTree = *tree
		}
	}

	ruleFailure.SetRuntimeProcessDetails(runtimeProcessDetails)

	// Enrich RuntimeAlertK8sDetails
	runtimek8sdetails := ruleFailure.GetRuntimeAlertK8sDetails()
	if runtimek8sdetails.Image == "" {
		runtimek8sdetails.Image = ruleFailure.GetTriggerEvent().Runtime.ContainerImageName
	}

	if runtimek8sdetails.ImageDigest == "" {
		runtimek8sdetails.ImageDigest = ruleFailure.GetTriggerEvent().Runtime.ContainerImageDigest
	}

	if runtimek8sdetails.Namespace == "" {
		runtimek8sdetails.Namespace = ruleFailure.GetTriggerEvent().K8s.Namespace
	}

	if runtimek8sdetails.PodName == "" {
		runtimek8sdetails.PodName = ruleFailure.GetTriggerEvent().K8s.PodName
	}

	if runtimek8sdetails.PodNamespace == "" {
		runtimek8sdetails.PodNamespace = ruleFailure.GetTriggerEvent().K8s.Namespace
	}

	if runtimek8sdetails.ContainerName == "" {
		runtimek8sdetails.ContainerName = ruleFailure.GetTriggerEvent().K8s.ContainerName
	}

	if runtimek8sdetails.ContainerID == "" {
		runtimek8sdetails.ContainerID = ruleFailure.GetTriggerEvent().Runtime.ContainerID
	}

	if runtimek8sdetails.HostNetwork == nil {
		hostNetwork := ruleFailure.GetTriggerEvent().K8s.HostNetwork
		runtimek8sdetails.HostNetwork = &hostNetwork
	}

	ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)

	if cloudServices := rm.dnsManager.ResolveContainerProcessToCloudServices(ruleFailure.GetTriggerEvent().Runtime.ContainerID, runtimeProcessDetails.ProcessTree.PID); cloudServices != nil {
		ruleFailure.SetCloudServices(cloudServices.ToSlice())
	}

	if rm.enricher != nil && !reflect.ValueOf(rm.enricher).IsNil() {
		rm.enricher.EnrichRuleFailure(ruleFailure)
	}

	return ruleFailure
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

func (rm *RuleManager) EvaluateRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string {
	results := []string{}

	creator := rm.ruleBindingCache.GetRuleCreator()
	rules := creator.CreateRulesByEventType(eventType)

	for _, rule := range rules {
		rule, ok := rule.(ruleengine.RuleCondition)
		if !ok {
			continue
		}

		if ok, _ := rule.EvaluateRule(eventType, event, rm.objectCache.K8sObjectCache()); ok {
			results = append(results, rule.ID())
		}
	}

	return results
}
