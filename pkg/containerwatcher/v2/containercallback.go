package containerwatcher

import (
	"fmt"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
)

// containerCallback handles container events synchronously
func (cw *ContainerWatcher) containerCallback(notif containercollection.PubSubEvent) {
	logger.L().Info("ContainerWatcher.containerCallback - received container event", helpers.String("event", fmt.Sprintf("%+v", notif)), helpers.String("container", fmt.Sprintf("%+v", notif.Container)))
	if notif.Container == nil || notif.Container.Runtime.ContainerID == "" {
		logger.L().Info("ContainerWatcher.containerCallback - container is nil or has empty ContainerID")
		return
	}
	// check if the container should be ignored
	if cw.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		logger.L().Info("ContainerWatcher.containerCallback - container ignored",
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("podName", notif.Container.K8s.PodName),
			helpers.String("containerID", notif.Container.Runtime.ContainerID))
		// avoid loops when the container is being removed
		if notif.Type == containercollection.EventTypeAddContainer {
			cw.unregisterContainer(notif.Container)
		}
		return
	}
	// scale up the pool size if needed pkg/config/config.go:66
	logger.L().Info("ContainerWatcher.containerCallback - processing container",
		helpers.String("containerID", notif.Container.Runtime.ContainerID),
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("podName", notif.Container.K8s.PodName),
		helpers.Int("callbackCount", len(cw.callbacks)))
	for _, callback := range cw.callbacks {
		cw.pool.Submit(func() {
			callback(notif)
		}, utils.FuncName(callback))
	}
}

// containerCallbackAsync handles container events asynchronously
func (cw *ContainerWatcher) containerCallbackAsync(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.Runtime.ContainerID)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Debug("ContainerWatcher.containerCallback - add container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		cw.metrics.ReportContainerStart()

		// Set shared watched container data
		go cw.setSharedWatchedContainerData(notif.Container)
	case containercollection.EventTypeRemoveContainer:
		logger.L().Debug("ContainerWatcher.containerCallback - remove container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		cw.metrics.ReportContainerStop()
		cw.objectCache.K8sObjectCache().DeleteSharedContainerData(notif.Container.Runtime.ContainerID)
	}
}

// setSharedWatchedContainerData sets shared container data with retry logic
func (cw *ContainerWatcher) setSharedWatchedContainerData(container *containercollection.Container) {
	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	var sharedWatchedContainerData *objectcache.WatchedContainerData
	err := backoff.Retry(func() error {
		data, err := cw.getSharedWatchedContainerData(container)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("received nil container data")
		}
		sharedWatchedContainerData = data
		return nil
	}, backoff.NewExponentialBackOff())

	if err != nil {
		logger.L().Error("ContainerWatcher.containerCallback - error getting shared watched container data", helpers.Error(err))
		return // Exit early on error
	}

	if sharedWatchedContainerData == nil {
		logger.L().Error("ContainerWatcher.containerCallback - shared watched container data is nil after retry")
		return
	}

	cw.objectCache.K8sObjectCache().SetSharedContainerData(container.Runtime.ContainerID, sharedWatchedContainerData)
}

// getSharedWatchedContainerData gets shared container data from Kubernetes
func (cw *ContainerWatcher) getSharedWatchedContainerData(container *containercollection.Container) (*objectcache.WatchedContainerData, error) {
	watchedContainer := objectcache.WatchedContainerData{
		ContainerID: container.Runtime.ContainerID,
		// we get ImageID and ImageTag from the pod spec for consistency with operator
	}

	wl, err := cw.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return nil, fmt.Errorf("failed to get workload: %w", err)
	}
	// make sure the pod is not pending (otherwise ImageID is empty in containerStatuses)
	podStatus, err := wl.GetPodStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get pod status: %w", err)
	}
	if podStatus.Phase == "Pending" {
		return nil, fmt.Errorf("pod is still pending")
	}
	pod := wl.(*workloadinterface.Workload)
	// fill container type, index and names
	if watchedContainer.ContainerType == objectcache.Unknown {
		if err := watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName); err != nil {
			return nil, fmt.Errorf("failed to set container info: %w", err)
		}
	}
	// find parentWlid
	kind, name, err := cw.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate parent workload: %w", err)
	}
	parentWorkload, err := cw.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(cw.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return nil, fmt.Errorf("failed to validate wlid: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
	// find parent selector
	selector, err := w.GetSelector()
	if err != nil {
		return nil, fmt.Errorf("failed to get selector: %w", err)
	}
	watchedContainer.ParentWorkloadSelector = selector
	preRunning := time.Unix(0, int64(container.Runtime.ContainerStartedAt)).Before(cw.agentStartTime)
	watchedContainer.PreRunningContainer = preRunning
	// find instanceID - this has to be the last one
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod, cw.cfg.ExcludeJsonPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance id: %w", err)
	}
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
	if watchedContainer.InstanceID == nil {
		return nil, fmt.Errorf("failed to find instance id for container %s", container.K8s.ContainerName)
	}
	return &watchedContainer, nil
}

// unregisterContainer unregisters a container from monitoring
func (cw *ContainerWatcher) unregisterContainer(container *containercollection.Container) {
	if cw.ruleManagedPods.Contains(utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)) {
		// the container should still be monitored
		logger.L().Debug("ContainerWatcher - container should still be monitored",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName),
		)
		return
	}

	logger.L().Debug("ContainerWatcher - stopping to monitor on container", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName))

	cw.containerCollection.RemoveContainer(container.Runtime.ContainerID)
	cw.objectCache.K8sObjectCache().DeleteSharedContainerData(container.Runtime.ContainerID)
}
