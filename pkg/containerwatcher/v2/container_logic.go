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

const (
	MaxSniffingTimeLabel = "kubescape.io/max-sniffing-time"
)

// containerCallback handles container events synchronously
func (ncw *NewContainerWatcher) containerCallback(notif containercollection.PubSubEvent) {
	logger.L().Info("NewContainerWatcher.containerCallback - received container event", helpers.String("event", fmt.Sprintf("%+v", notif)), helpers.String("container", fmt.Sprintf("%+v", notif.Container)))
	if notif.Container == nil || notif.Container.Runtime.ContainerID == "" {
		logger.L().Info("NewContainerWatcher.containerCallback - container is nil or has empty ContainerID")
		return
	}
	// check if the container should be ignored
	if ncw.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		logger.L().Info("NewContainerWatcher.containerCallback - container ignored",
			helpers.String("namespace", notif.Container.K8s.Namespace),
			helpers.String("podName", notif.Container.K8s.PodName),
			helpers.String("containerID", notif.Container.Runtime.ContainerID))
		// avoid loops when the container is being removed
		if notif.Type == containercollection.EventTypeAddContainer {
			ncw.unregisterContainer(notif.Container)
		}
		return
	}
	// scale up the pool size if needed pkg/config/config.go:66
	logger.L().Info("NewContainerWatcher.containerCallback - processing container",
		helpers.String("containerID", notif.Container.Runtime.ContainerID),
		helpers.String("namespace", notif.Container.K8s.Namespace),
		helpers.String("podName", notif.Container.K8s.PodName),
		helpers.Int("callbackCount", len(ncw.callbacks)))
	for _, callback := range ncw.callbacks {
		ncw.pool.Submit(func() {
			callback(notif)
		}, utils.FuncName(callback))
	}
}

// containerCallbackAsync handles container events asynchronously
func (ncw *NewContainerWatcher) containerCallbackAsync(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.Runtime.ContainerID)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Debug("NewContainerWatcher.containerCallback - add container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		// Check if Pod has a label of max sniffing time
		sniffingTime := utils.AddJitter(ncw.cfg.MaxSniffingTime, ncw.cfg.MaxJitterPercentage)
		if podLabelMaxSniffingTime, ok := notif.Container.K8s.PodLabels[MaxSniffingTimeLabel]; ok {
			if duration, err := time.ParseDuration(podLabelMaxSniffingTime); err == nil {
				sniffingTime = duration
			} else {
				logger.L().Debug("NewContainerWatcher.containerCallback - parsing sniffing time in label", helpers.Error(err), helpers.String("podLabelMaxSniffingTime", podLabelMaxSniffingTime))
			}
		}

		// Set shared watched container data
		go ncw.setSharedWatchedContainerData(notif.Container)

		time.AfterFunc(sniffingTime, func() {
			logger.L().Debug("NewContainerWatcher.containerCallback - monitoring time ended",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID),
				helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
				helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
			ncw.unregisterContainer(notif.Container)
		})
	case containercollection.EventTypeRemoveContainer:
		logger.L().Debug("NewContainerWatcher.containerCallback - remove container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		ncw.objectCache.K8sObjectCache().DeleteSharedContainerData(notif.Container.Runtime.ContainerID)
	}
}

// setSharedWatchedContainerData sets shared container data with retry logic
func (ncw *NewContainerWatcher) setSharedWatchedContainerData(container *containercollection.Container) {
	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	var sharedWatchedContainerData *objectcache.WatchedContainerData
	err := backoff.Retry(func() error {
		data, err := ncw.getSharedWatchedContainerData(container)
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
		logger.L().Error("NewContainerWatcher.containerCallback - error getting shared watched container data", helpers.Error(err))
		return // Exit early on error
	}

	if sharedWatchedContainerData == nil {
		logger.L().Error("NewContainerWatcher.containerCallback - shared watched container data is nil after retry")
		return
	}

	ncw.objectCache.K8sObjectCache().SetSharedContainerData(container.Runtime.ContainerID, sharedWatchedContainerData)
}

// getSharedWatchedContainerData gets shared container data from Kubernetes
func (ncw *NewContainerWatcher) getSharedWatchedContainerData(container *containercollection.Container) (*objectcache.WatchedContainerData, error) {
	watchedContainer := objectcache.WatchedContainerData{
		ContainerID: container.Runtime.ContainerID,
		// we get ImageID and ImageTag from the pod spec for consistency with operator
	}

	wl, err := ncw.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
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
	kind, name, err := ncw.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate parent workload: %w", err)
	}
	parentWorkload, err := ncw.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(ncw.clusterName)
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
	preRunning := time.Unix(0, int64(container.Runtime.ContainerStartedAt)).Before(ncw.agentStartTime)
	watchedContainer.PreRunningContainer = preRunning
	// find instanceID - this has to be the last one
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod, ncw.cfg.ExcludeJsonPaths)
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
func (ncw *NewContainerWatcher) unregisterContainer(container *containercollection.Container) {
	if ncw.ruleManagedPods.Contains(utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)) {
		// the container should still be monitored
		logger.L().Debug("NewContainerWatcher - container should still be monitored",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName),
		)
		return
	}

	logger.L().Debug("NewContainerWatcher - stopping to monitor on container", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName))

	ncw.containerCollection.RemoveContainer(container.Runtime.ContainerID)
	ncw.objectCache.K8sObjectCache().DeleteSharedContainerData(container.Runtime.ContainerID)
}
