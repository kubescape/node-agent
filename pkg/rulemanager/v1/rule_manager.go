package rulemanager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dustin/go-humanize"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
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
	storageUtils "github.com/kubescape/storage/pkg/utils"
	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Max file size to calculate hash is 50MB.
	maxFileSize int64 = 50 * 1024 * 1024
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
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
	containerMutexes         storageUtils.MapMutex[string] // key is k8sContainerID
	podToWlid                maps.SafeMap[string, string]  // key is namespace/podName
	nodeName                 string
	clusterName              string
	containerIdToShimPid     maps.SafeMap[string, uint32]
	containerIdToPid         maps.SafeMap[string, uint32]
	enricher                 ruleenginetypes.Enricher
	processManager           processmanager.ProcessManagerClient
	dnsManager               dnsmanager.DNSResolver
}

var _ rulemanager.RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, ruleBindingCache bindingcache.RuleBindingCache, objectCache objectcache.ObjectCache, exporter exporters.Exporter, metrics metricsmanager.MetricsManager, nodeName string, clusterName string, processManager processmanager.ProcessManagerClient, dnsManager dnsmanager.DNSResolver, enricher ruleenginetypes.Enricher) (*RuleManager, error) {
	return &RuleManager{
		cfg:               cfg,
		ctx:               ctx,
		k8sClient:         k8sClient,
		containerMutexes:  storageUtils.NewMapMutex[string](),
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
		logger.L().Debug("RuleManager - failed to get pod", helpers.Error(err),
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
				logger.L().Debug("RuleManager - syscallPeekFunc is not set", helpers.String("container ID", watchedContainer.ContainerID))
				continue
			}

			if watchedContainer.NsMntId == 0 {
				logger.L().Debug("RuleManager - mount namespace ID is not set", helpers.String("container ID", watchedContainer.ContainerID))
			}

			var syscalls []string
			if syscallsFromFunc, err := rm.syscallPeekFunc(watchedContainer.NsMntId); err == nil {
				syscalls = syscallsFromFunc
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
					Pid: container.ContainerPid(),
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
	// fill container type, index and names
	if watchedContainer.ContainerType == utils.Unknown {
		if err := watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName); err != nil {
			return fmt.Errorf("failed to set container info: %w", err)
		}
	}
	// find instanceID - this has to be the last one
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
	return nil
}

func (rm *RuleManager) startRuleManager(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "RuleManager.startRuleManager")
	defer span.End()

	syncChannel := make(chan error, 10)
	rm.watchedContainerChannels.Set(container.Runtime.ContainerID, syncChannel)

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:    container.Runtime.ContainerID,
		ImageID:        container.Runtime.ContainerImageDigest,
		ImageTag:       container.Runtime.ContainerImageName,
		SyncChannel:    syncChannel,
		K8sContainerID: k8sContainerID,
		NsMntId:        container.Mntns,
	}

	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated.
	if err := backoff.Retry(func() error {
		return rm.ensureInstanceID(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Debug("RuleManager - failed to ensure instanceID", helpers.Error(err),
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
	// check if the container should be ignored
	if rm.cfg.SkipNamespace(notif.Container.K8s.Namespace) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if rm.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("RuleManager - container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}
		podID := utils.CreateK8sPodID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName)
		if !rm.podToWlid.Has(podID) {
			w, err := rm.getWorkloadIdentifier(notif.Container.K8s.Namespace, notif.Container.K8s.PodName)
			if err != nil {
				logger.L().Debug("RuleManager - failed to get workload identifier", helpers.Error(err), helpers.String("k8s workload", notif.Container.K8s.PodName))
			} else {
				rm.podToWlid.Set(podID, w)
			}
		}
		rm.trackedContainers.Add(k8sContainerID)
		shim, err := utils.GetProcessStat(int(notif.Container.ContainerPid()))
		if err != nil {
			logger.L().Warning("RuleManager - failed to get shim process", helpers.Error(err))
		} else {
			rm.containerIdToShimPid.Set(notif.Container.Runtime.ContainerID, uint32(shim.PPID))
		}
		rm.containerIdToPid.Set(notif.Container.Runtime.ContainerID, notif.Container.ContainerPid())
		go rm.startRuleManager(rm.ctx, notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		channel := rm.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		rm.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
		rm.podToWlid.Delete(utils.CreateK8sPodID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName))
		rm.containerIdToShimPid.Delete(notif.Container.Runtime.ContainerID)
		rm.containerIdToPid.Delete(notif.Container.Runtime.ContainerID)
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

		if rule.EvaluateRule(eventType, event, rm.objectCache.K8sObjectCache()) {
			results = append(results, rule.ID())
		}
	}

	return results
}
