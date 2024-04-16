package rulemanager

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/exporters"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/rulemanager"
	"node-agent/pkg/utils"
	"path/filepath"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	"github.com/dustin/go-humanize"
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
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"

	storageUtils "github.com/kubescape/storage/pkg/utils"
)

type RuleManager struct {
	cfg                      config.Config
	watchedContainerChannels maps.SafeMap[string, chan error] // key is k8sContainerID
	ruleBindingCache         bindingcache.RuleBindingCache
	trackedContainers        mapset.Set[string] // key is k8sContainerID
	k8sClient                k8sclient.K8sClientInterface
	ctx                      context.Context
	objectCache              objectcache.ObjectCache
	exporter                 exporters.Exporter
	metrics                  metricsmanager.MetricsManager
	preRunningContainerIDs   mapset.Set[string] // key is k8sContainerID
	cachedPods               mapset.Set[string] // key is namespace/podName
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	containerMutexes         storageUtils.MapMutex[string] // key is k8sContainerID
	podInCacheMutexes        storageUtils.MapMutex[string] // key is namespace+podName
	podToWlid                maps.SafeMap[string, string]
	nodeName                 string
	clusterName              string
	containerIdToShimPid     maps.SafeMap[string, uint32]
}

var _ rulemanager.RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, ruleBindingCache bindingcache.RuleBindingCache, objectCache objectcache.ObjectCache, exporter exporters.Exporter, metrics metricsmanager.MetricsManager, preRunningContainersIDs mapset.Set[string], nodeName string, clusterName string) (*RuleManager, error) {
	return &RuleManager{
		cfg:                    cfg,
		ctx:                    ctx,
		k8sClient:              k8sClient,
		containerMutexes:       storageUtils.NewMapMutex[string](),
		podInCacheMutexes:      storageUtils.NewMapMutex[string](),
		trackedContainers:      mapset.NewSet[string](),
		ruleBindingCache:       ruleBindingCache,
		objectCache:            objectCache,
		exporter:               exporter,
		metrics:                metrics,
		preRunningContainerIDs: preRunningContainersIDs,
		cachedPods:             mapset.NewSet[string](),
		nodeName:               nodeName,
		clusterName:            clusterName,
	}, nil
}

func (rm *RuleManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	logger.L().Debug("RuleManager - start monitor on container",
		helpers.Int("container index", watchedContainer.ContainerIndex),
		helpers.String("container ID", watchedContainer.ContainerID),
		helpers.String("k8s workload", watchedContainer.K8sContainerID))

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
		// failed to get pod
		return err
	}
	syscallTicker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-syscallTicker.C:
			if rm.syscallPeekFunc == nil {
				logger.L().Error("RuleManager - syscallPeekFunc is not set", helpers.String("container ID", watchedContainer.ContainerID))
				continue
			}

			if watchedContainer.NsMntId == 0 {
				logger.L().Error("RuleManager - mount namespace ID is not set", helpers.String("container ID", watchedContainer.ContainerID))
			}

			var syscalls []string
			if syscallsFromFunc, err := rm.syscallPeekFunc(watchedContainer.NsMntId); err == nil {
				syscalls = syscallsFromFunc
			}

			if !rm.isCached(pod.GetNamespace(), pod.GetName()) {
				logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", pod.GetNamespace()), helpers.String("name", pod.GetName()))
				continue
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
					Pid: container.Pid,
					// TODO: Figure out how to get UID, GID and comm from the syscall.
					// Uid:         container.OciConfig.Process.User.UID,
					// Gid:         container.OciConfig.Process.User.GID,
					// Comm:        container.OciConfig.Process.Args[0],
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

func (rm *RuleManager) ensureInstanceID(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	if watchedContainer.InstanceID != nil {
		return nil
	}

	wl, err := rm.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return fmt.Errorf("failed to get workload: %w", err)
	}

	pod := wl.(*workloadinterface.Workload)

	// find instanceID
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return fmt.Errorf("failed to generate instanceID: %w", err)
	}

	watchedContainer.InstanceID = instanceIDs[0]
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
	// find container type and index
	if watchedContainer.ContainerType == utils.Unknown {
		watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName)
	}

	return nil
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

	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated.
	if err := backoff.Retry(func() error {
		return rm.ensureInstanceID(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Ctx(ctx).Error("RuleManager - failed to ensure instanceID", helpers.Error(err),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	if err := rm.monitorContainer(ctx, container, watchedContainer); err != nil {
		logger.L().Debug("RuleManager - stop monitor on container", helpers.String("reason", err.Error()),
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
	rm.trackedContainers.Remove(watchedContainer.K8sContainerID)
	rm.watchedContainerChannels.Delete(watchedContainer.ContainerID)
}

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
		if !rm.podToWlid.Has(notif.Container.K8s.PodName) {
			wlid, err := rm.getWorkloadIdentifier(notif.Container.K8s.Namespace, notif.Container.K8s.PodName)
			if err != nil {
				logger.L().Debug("RuleManager - failed to get workload identifier", helpers.Error(err), helpers.String("k8s workload", notif.Container.K8s.PodName))
			} else {
				rm.podToWlid.Set(notif.Container.K8s.PodName, wlid)
			}
		}
		rm.trackedContainers.Add(k8sContainerID)
		shim, err := utils.GetProcessStat(int(notif.Container.Pid))
		if err != nil {
			logger.L().Warning("RuleManager - failed to get shim process", helpers.Error(err))
		} else {
			rm.containerIdToShimPid.Set(notif.Container.Runtime.ContainerID, uint32(shim.PPID))
		}
		go rm.startRuleManager(rm.ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		channel := rm.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		rm.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
		rm.podToWlid.Delete(notif.Container.K8s.PodName)
		rm.containerIdToShimPid.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (rm *RuleManager) getWorkloadIdentifier(podNamespace, podName string) (string, error) {
	wl, err := rm.k8sClient.GetWorkload(podNamespace, "Pod", podName)
	if err != nil {
		return "", fmt.Errorf("failed to get workload: %w", err)
	}
	pod := wl.(*workloadinterface.Workload)

	// find parentWlid
	kind, name, err := rm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return "", fmt.Errorf("failed to calculate workload parent: %w", err)
	}
	parentWorkload, err := rm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return "", fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	generatedWlid := w.GenerateWlid(rm.clusterName)
	err = wlid.IsWlidValid(generatedWlid)
	if err != nil {
		return "", fmt.Errorf("failed to validate WLID: %w", err)
	}

	return generatedWlid, nil
}

func (rm *RuleManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	rm.syscallPeekFunc = peek
}

func (rm *RuleManager) ReportCapability(k8sContainerID string, event tracercapabilitiestype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportCapability event")
		return
	}
	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
		return
	}

	// list capability rules
	rules := rm.ruleBindingCache.ListRulesForPod(event.GetNamespace(), event.GetPod())

	rm.processEvent(utils.CapabilitiesEventType, &event, rules)
}

func (rm *RuleManager) ReportFileExec(k8sContainerID string, event tracerexectype.Event) {
	if event.GetNamespace() == "" || event.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from ReportFileExec event")
		return
	}
	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
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
	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
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
	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
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
	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
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

	if !rm.isCached(event.GetNamespace(), event.GetPod()) {
		logger.L().Error("isCached - failed to get pod from cache", helpers.String("namespace", event.GetNamespace()), helpers.String("name", event.GetPod()))
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
			res.SetWorkloadDetails(rm.podToWlid.Get(res.GetRuntimeAlertK8sDetails().PodName))
			res = rm.enrichRuleFailure(res)
			rm.exporter.SendRuleAlert(res)
			rm.metrics.ReportRuleAlert(rule.Name())
		}
		rm.metrics.ReportRuleProcessed(rule.Name())
	}
}

func (rm *RuleManager) enrichRuleFailure(ruleFailure ruleengine.RuleFailure) ruleengine.RuleFailure {
	path, err := utils.GetPathFromPid(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID)
	hostPath := ""
	if err != nil {
		path = ""
	} else {
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID, path))
	}

	// Enrich BaseRuntimeAlert
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()

	baseRuntimeAlert.Timestamp = time.Unix(int64(ruleFailure.GetTriggerEvent().Timestamp)/1e9, 0)

	if baseRuntimeAlert.MD5Hash == "" && hostPath != "" {
		md5hash, err := utils.CalculateMD5FileHash(hostPath)
		if err != nil {
			md5hash = ""
		}
		baseRuntimeAlert.MD5Hash = md5hash
	}

	if baseRuntimeAlert.SHA1Hash == "" && hostPath != "" {
		sha1hash, err := utils.CalculateSHA1FileHash(hostPath)
		if err != nil {
			sha1hash = ""
		}

		baseRuntimeAlert.SHA1Hash = sha1hash
	}

	if baseRuntimeAlert.SHA256Hash == "" && hostPath != "" {
		sha256hash, err := utils.CalculateSHA256FileHash(hostPath)
		if err != nil {
			sha256hash = ""
		}

		baseRuntimeAlert.SHA256Hash = sha256hash
	}

	if baseRuntimeAlert.Size == nil && hostPath != "" {
		size, err := utils.GetFileSize(hostPath)
		if err != nil {
			sizeStr := ""
			baseRuntimeAlert.Size = &sizeStr
		} else {
			size := humanize.Bytes(uint64(size))
			baseRuntimeAlert.Size = &size
		}
	}

	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := ruleFailure.GetRuntimeProcessDetails()
	if runtimeProcessDetails.ProcessTree.Cmdline == "" {
		commandLine, err := utils.GetCmdlineByPid(int(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID))
		if err != nil {
			runtimeProcessDetails.ProcessTree.Cmdline = ""
		} else {
			runtimeProcessDetails.ProcessTree.Cmdline = *commandLine
		}
	}

	if runtimeProcessDetails.ProcessTree.PPID == 0 {
		parent, err := utils.GetProcessStat(int(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID))
		if err != nil {
			runtimeProcessDetails.ProcessTree.PPID = 0
		} else {
			runtimeProcessDetails.ProcessTree.PPID = uint32(parent.PPID)
		}

		if runtimeProcessDetails.ProcessTree.Pcomm == "" {
			if err == nil {
				runtimeProcessDetails.ProcessTree.Pcomm = parent.Comm
			} else {
				runtimeProcessDetails.ProcessTree.Pcomm = ""
			}
		}
	}

	if runtimeProcessDetails.ProcessTree.PID == 0 {
		runtimeProcessDetails.ProcessTree.PID = ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID
	}

	if runtimeProcessDetails.ProcessTree.Comm == "" {
		comm, err := utils.GetCommFromPid(ruleFailure.GetRuntimeProcessDetails().ProcessTree.PID)
		if err != nil {
			comm = ""
		}
		runtimeProcessDetails.ProcessTree.Comm = comm
	}

	if rm.containerIdToShimPid.Has(ruleFailure.GetRuntimeProcessDetails().ContainerID) {
		shimPid := rm.containerIdToShimPid.Get(ruleFailure.GetRuntimeProcessDetails().ContainerID)
		tree, err := utils.CreateProcessTree(&runtimeProcessDetails.ProcessTree, shimPid)
		if err == nil {
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
		runtimek8sdetails.ContainerName = ruleFailure.GetTriggerEvent().Runtime.ContainerName
	}

	if runtimek8sdetails.ContainerID == "" {
		runtimek8sdetails.ContainerID = ruleFailure.GetTriggerEvent().Runtime.ContainerID
	}

	if runtimek8sdetails.HostNetwork == nil {
		hostNetwork := ruleFailure.GetTriggerEvent().K8s.HostNetwork
		runtimek8sdetails.HostNetwork = &hostNetwork
	}

	ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)

	return ruleFailure
}

func (rm *RuleManager) isCached(namespace, name string) bool {
	return true

	podName := fmt.Sprintf("%s/%s", namespace, name)

	// this will prevent multiple goroutines from waiting for the same pod to be cached
	// first, try to read lock the pod
	rm.podInCacheMutexes.RLock(podName)

	if rm.cachedPods.Contains(podName) {
		rm.podInCacheMutexes.RUnlock(podName)
		return true
	}
	rm.podInCacheMutexes.RUnlock(podName)

	// if the pod is not cached, lock it for writing
	rm.podInCacheMutexes.Lock(podName)
	defer rm.podInCacheMutexes.Unlock(podName)

	// check again (because another goroutine might have cached the pod while we were waiting for the lock)
	if rm.cachedPods.Contains(podName) {
		return true
	}

	// wait for pod to be cached
	if err := backoff.Retry(func() error {
		// if !rm.objectCache.K8sObjectCache().IsCached("Pod", namespace, name) {
		// 	return fmt.Errorf("pod %s/%s not found in K8sObjectCache", namespace, name)
		// }

		return nil
	}, backoff.NewExponentialBackOff()); err != nil {
		return false
	}

	rm.cachedPods.Add(podName)
	return true
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
