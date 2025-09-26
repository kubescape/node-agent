package containerprofilemanager

import (
	"errors"
	"runtime"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// monitorContainer monitors a container and saves its profile periodically
func (cpm *ContainerProfileManager) monitorContainer(container *containercollection.Container, watchedContainer *objectcache.WatchedContainerData) error {
	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// Adjust ticker after first tick for faster initial updates
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(utils.AddJitter(cpm.cfg.UpdateDataPeriod, cpm.cfg.MaxJitterPercentage))
			}

			watchedContainer.SetStatus(objectcache.WatchedContainerStatusReady)
			if err := cpm.saveProfile(watchedContainer, container); err != nil {
				if handledErr := cpm.handleSaveProfileError(err, watchedContainer, container); handledErr != nil {
					return handledErr
				}
			}

		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, ContainerHasTerminatedError):
				if err := cpm.saveProfile(watchedContainer, container); err != nil {
					logger.L().Error("failed to save container profile on termination", helpers.Error(err),
						helpers.String("containerID", watchedContainer.ContainerID),
						helpers.String("containerName", container.Runtime.ContainerName),
						helpers.String("workloadID", watchedContainer.Wlid),
						helpers.String("status", string(watchedContainer.GetStatus())),
						helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())))
				}
				// Signal ack to lifecycle goroutine
				if watchedContainer.AckChan != nil {
					watchedContainer.AckChan <- struct{}{}
				}
				return ContainerHasTerminatedError

			case errors.Is(err, ContainerReachedMaxTime):
				watchedContainer.SetStatus(objectcache.WatchedContainerStatusCompleted)
				if err := cpm.saveProfile(watchedContainer, container); err != nil {
					logger.L().Error("failed to save container profile on max time", helpers.Error(err),
						helpers.String("containerID", watchedContainer.ContainerID),
						helpers.String("containerName", container.Runtime.ContainerName),
						helpers.String("workloadID", watchedContainer.Wlid),
						helpers.String("status", string(watchedContainer.GetStatus())),
						helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())))
				}
				// Signal ack to lifecycle goroutine
				if watchedContainer.AckChan != nil {
					watchedContainer.AckChan <- struct{}{}
				}
				return ContainerReachedMaxTime

			case errors.Is(err, ProfileRequiresSplit):
				if err := cpm.saveProfile(watchedContainer, container); err != nil {
					if handledErr := cpm.handleSaveProfileError(err, watchedContainer, container); handledErr != nil {
						return handledErr
					}
				}

			default:
				// Handle queue errors (ObjectTooLargeError or ObjectCompletedError)
				if err := cpm.handleSaveProfileError(err, watchedContainer, container); err != nil {
					return err
				}
			}
		}
	}
}

// handleSaveProfileError handles common error cases for saveProfile operations
func (cpm *ContainerProfileManager) handleSaveProfileError(err error, watchedContainer *objectcache.WatchedContainerData, container *containercollection.Container) error {
	if err.Error() == file.ObjectTooLargeError.Error() {
		watchedContainer.SetStatus(objectcache.WatchedContainerStatusTooLarge)
		cpm.deleteContainer(container)
		cpm.notifyContainerEndOfLife(container)
		return file.ObjectTooLargeError
	} else if err.Error() == file.ObjectCompletedError.Error() {
		watchedContainer.SetStatus(objectcache.WatchedContainerStatusCompleted)
		cpm.deleteContainer(container)
		cpm.notifyContainerEndOfLife(container)
		return file.ObjectCompletedError
	} else {
		logger.L().Error("failed to save container profile", helpers.Error(err),
			helpers.String("containerID", watchedContainer.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("workloadID", watchedContainer.Wlid),
			helpers.String("status", string(watchedContainer.GetStatus())),
			helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())))
	}
	// If the error is not something we can handle, we return nil to continue the loop
	return nil
}

// saveProfile saves the container profile using the with pattern for safe access
func (cpm *ContainerProfileManager) saveProfile(watchedContainer *objectcache.WatchedContainerData, container *containercollection.Container) error {
	return cpm.withContainerNoSizeUpdate(watchedContainer.ContainerID, func(data *containerData) error {
		return cpm.saveContainerProfile(watchedContainer, container, data)
	})
}

// saveContainerProfile saves the container profile to storage
func (cpm *ContainerProfileManager) saveContainerProfile(watchedContainer *objectcache.WatchedContainerData, container *containercollection.Container, containerData *containerData) error {
	if watchedContainer == nil {
		return errors.New("watched container data is nil")
	}

	slug, err := watchedContainer.InstanceID.GetOneTimeSlug(false)
	if err != nil {
		logger.L().Error("failed to get slug for container profile", helpers.Error(err))
		return err
	}

	containerInfo := watchedContainer.ContainerInfos[watchedContainer.ContainerType][watchedContainer.ContainerIndex]
	seccompProfile, err := cpm.seccompManager.GetSeccompProfile(containerInfo.Name, watchedContainer.SeccompProfilePath)
	if err != nil {
		logger.L().Debug("failed to get seccomp profile for container",
			helpers.Error(err),
			helpers.String("slug", slug),
			helpers.Int("container index", watchedContainer.ContainerIndex),
			helpers.String("container ID", watchedContainer.ContainerID),
			helpers.String("k8s workload", watchedContainer.Wlid))
	}

	// Check if there are any dropped events
	if containerData.droppedEvents {
		watchedContainer.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusPartial)
	}

	if containerData.isEmpty() { // TODO: Also check if the seccomp profile is new (currently not implemented)
		return nil
	}

	// Update timestamps before saving
	watchedContainer.PreviousReportTimestamp = watchedContainer.CurrentReportTimestamp
	watchedContainer.CurrentReportTimestamp = time.Now()

	containerProfile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      slug,
			Namespace: container.K8s.Namespace,
			Annotations: map[string]string{
				helpersv1.InstanceIDMetadataKey:              watchedContainer.InstanceID.GetStringFormatted(),
				helpersv1.WlidMetadataKey:                    watchedContainer.Wlid,
				helpersv1.CompletionMetadataKey:              string(watchedContainer.GetCompletionStatus()),
				helpersv1.StatusMetadataKey:                  string(watchedContainer.GetStatus()),
				helpersv1.ContainerTypeMetadataKey:           watchedContainer.ContainerType.String(),
				helpersv1.ReportSeriesIdMetadataKey:          watchedContainer.SeriesID,
				helpersv1.PreviousReportTimestampMetadataKey: watchedContainer.PreviousReportTimestamp.String(),
				helpersv1.ReportTimestampMetadataKey:         watchedContainer.CurrentReportTimestamp.String(),
			},
			Labels: objectcache.GetLabels(watchedContainer, false),
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures:        []string{runtime.GOARCH},
			ImageID:              containerInfo.ImageID,
			ImageTag:             containerInfo.ImageTag,
			SeccompProfile:       seccompProfile,
			Capabilities:         containerData.getCapabilities(),
			Execs:                containerData.getExecs(),
			Opens:                containerData.getOpens(),
			Syscalls:             containerData.getSyscalls(),
			Endpoints:            containerData.getEndpoints(),
			PolicyByRuleId:       containerData.getRulePolicies(),
			IdentifiedCallStacks: containerData.getCallStacks(),
			Egress:               containerData.getEgressNetworkNeighbors(container.K8s.Namespace, cpm.k8sClient, cpm.dnsResolverClient),
			Ingress:              containerData.getIngressNetworkNeighbors(container.K8s.Namespace, cpm.k8sClient, cpm.dnsResolverClient),
			LabelSelector: metav1.LabelSelector{
				MatchLabels:      watchedContainer.ParentWorkloadSelector.MatchLabels,
				MatchExpressions: watchedContainer.ParentWorkloadSelector.MatchExpressions,
			},
		},
	}

	if err := cpm.enqueueContainerProfile(containerProfile, watchedContainer.ContainerID); err != nil {
		// Empty the container data to prevent reporting the same data again
		containerData.emptyEvents()
		return err
	}

	logger.L().Debug("container profile saved successfully",
		helpers.String("containerID", watchedContainer.ContainerID),
		helpers.String("containerName", container.Runtime.ContainerName),
		helpers.String("podName", container.K8s.PodName))

	// Empty the container data to prevent reporting the same data again
	containerData.emptyEvents()

	return nil
}

func (cpm *ContainerProfileManager) enqueueContainerProfile(containerProfile *v1beta1.ContainerProfile, containerID string) error {
	return cpm.queueData.Enqueue(containerProfile, containerID)
}

// OnQueueError implements the queue.ErrorCallback interface
// This method is called by the queue when it encounters ObjectTooLargeError or ObjectCompletedError
func (cpm *ContainerProfileManager) OnQueueError(_ *v1beta1.ContainerProfile, containerID string, err error) {
	err = cpm.withContainerNoSizeUpdate(containerID, func(data *containerData) error {
		if data.watchedContainerData != nil {
			data.watchedContainerData.SyncChannel <- err
		}
		return nil
	})

	if err != nil {
		// It's expected to happen in cases where there are multiple container profiles in the queue.
		logger.L().Debug("skipping sending queue error to container (container is not found)", helpers.String("containerID", containerID), helpers.Error(err))
	}
}
