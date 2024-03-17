package rulemanager

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/rulemanager"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff/v4"
	"go.opentelemetry.io/otel"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	storageUtils "github.com/kubescape/storage/pkg/utils"
)

type RuleManager struct {
	cfg                      config.Config
	clusterName              string
	ctx                      context.Context
	containerMutexes         storageUtils.MapMutex[string]    // key is k8sContainerID
	trackedContainers        mapset.Set[string]               // key is k8sContainerID
	watchedContainerChannels maps.SafeMap[string, chan error] // key is ContainerID
	k8sClient                k8sclient.K8sClientInterface
	storageClient            storage.StorageClient
	syscallPeekFunc          func(nsMountId uint64) ([]string, error)
}

var _ rulemanager.RuleManagerClient = (*RuleManager)(nil)

func CreateRuleManager(ctx context.Context, cfg config.Config, clusterName string, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient) (*RuleManager, error) {
	return &RuleManager{
		cfg:               cfg,
		clusterName:       clusterName,
		ctx:               ctx,
		k8sClient:         k8sClient,
		storageClient:     storageClient,
		containerMutexes:  storageUtils.NewMapMutex[string](),
		trackedContainers: mapset.NewSet[string](),
	}, nil
}

func (rm *RuleManager) monitorContainer(ctx context.Context, container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	for err := range watchedContainer.SyncChannel {
		switch {
		case errors.Is(err, utils.ContainerHasTerminatedError):
			return nil
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
		ContainerID:      container.Runtime.ContainerID,
		UpdateDataTicker: time.NewTicker(utils.AddRandomDuration(5, 10, rm.cfg.InitialDelay)), // get out of sync with the relevancy manager
		SyncChannel:      syncChannel,
		K8sContainerID:   k8sContainerID,
		NsMntId:          container.Mntns,
	}

	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	if err := backoff.Retry(func() error {
		// TODO: I'm not it is needed here
		return rm.ensureInstanceID(container, watchedContainer)
	}, backoff.NewExponentialBackOff()); err != nil {
		logger.L().Ctx(ctx).Error("ApplicationProfileManager - failed to ensure instanceID", helpers.Error(err),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
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
func (rm *RuleManager) ensureInstanceID(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	if watchedContainer.InstanceID != nil {
		return nil
	}
	wl, err := rm.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return fmt.Errorf("failed to get workload: %w", err)
	}
	pod := wl.(*workloadinterface.Workload)

	// get pod template hash
	watchedContainer.TemplateHash, _ = pod.GetLabel("pod-template-hash")

	// find parentWlid
	kind, name, err := rm.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return fmt.Errorf("failed to calculate workload parent: %w", err)
	}
	parentWorkload, err := rm.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(rm.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return fmt.Errorf("failed to validate WLID: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
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
		watchedContainer.SetContainerType(pod, container.K8s.ContainerName)
	}

	// FIXME ephemeralContainers are not supported yet
	return nil
}

func (rm *RuleManager) waitForContainer(k8sContainerID string) error {
	return backoff.Retry(func() error {
		if rm.trackedContainers.Contains(k8sContainerID) {
			return nil
		}
		return fmt.Errorf("container %s not found", k8sContainerID)
	}, backoff.NewExponentialBackOff())
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
		// container started
		// TODO:
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
	if err := rm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// process capability
}

func (rm *RuleManager) ReportFileExec(k8sContainerID string, event tracerexectype.Event) {
	if err := rm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// process file exec

}

func (rm *RuleManager) ReportFileOpen(k8sContainerID string, event traceropentype.Event) {
	if err := rm.waitForContainer(k8sContainerID); err != nil {
		return
	}
	// process file open

}
