package containerprofilemanager

import (
	"errors"
	"runtime"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (cpm *ContainerProfileManager) monitorContainer(container *containercollection.Container, watchedContainer *utils.WatchedContainerData) error {
	for {
		select {
		case <-watchedContainer.UpdateDataTicker.C:
			// Adjust ticker after first tick, at the first run we want to update data faster to show the profile is created.
			if !watchedContainer.InitialDelayExpired {
				watchedContainer.InitialDelayExpired = true
				watchedContainer.UpdateDataTicker.Reset(utils.AddJitter(cpm.cfg.UpdateDataPeriod, cpm.cfg.MaxJitterPercentage))
			}

			watchedContainer.SetStatus(utils.WatchedContainerStatusReady)
			if err := cpm.saveProfile(watchedContainer, container); err != nil {
				logger.L().Error("failed to save container profile", helpers.Error(err),
					helpers.String("containerID", watchedContainer.ContainerID),
					helpers.String("containerName", container.Runtime.ContainerName),
					helpers.String("workloadID", watchedContainer.Wlid),
					helpers.String("status", string(watchedContainer.GetStatus())),
					helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())),
				)

				if errors.Is(err, utils.TooLargeObjectError) {
					watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
					cpm.containerLocks.WithLock(container.Runtime.ContainerID, func() { // TODO: verify what is the effect of deleting the container here.
						cpm.containerIDToInfo.Delete(container.Runtime.ContainerID)
					})
					cpm.containerLocks.ReleaseLock(watchedContainer.ContainerID)
					cpm.notifyContainerEndOfLife(container)
					return utils.TooLargeObjectError
				} else if errors.Is(err, utils.ObjectCompleted) {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
					cpm.containerLocks.WithLock(container.Runtime.ContainerID, func() { // TODO: verify what is the effect of deleting the container here.
						cpm.containerIDToInfo.Delete(container.Runtime.ContainerID)
					})
					cpm.containerLocks.ReleaseLock(watchedContainer.ContainerID)
					cpm.notifyContainerEndOfLife(container)
					return utils.ObjectCompleted
				} else {
					// Because we failed to save the profile, we change the completion status to partial
					watchedContainer.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial) // TODO: yes?
				}

				// If we failed to save the profile, we will continue monitoring the container
				// return err
			}

		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				if err := cpm.saveProfile(watchedContainer, container); err != nil {
					logger.L().Error("failed to save container profile", helpers.Error(err),
						helpers.String("containerID", watchedContainer.ContainerID),
						helpers.String("containerName", container.Runtime.ContainerName),
						helpers.String("workloadID", watchedContainer.Wlid),
						helpers.String("status", string(watchedContainer.GetStatus())),
						helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())),
					)
				}
				return utils.ContainerHasTerminatedError
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				if err := cpm.saveProfile(watchedContainer, container); err != nil {
					logger.L().Error("failed to save container profile", helpers.Error(err),
						helpers.String("containerID", watchedContainer.ContainerID),
						helpers.String("containerName", container.Runtime.ContainerName),
						helpers.String("workloadID", watchedContainer.Wlid),
						helpers.String("status", string(watchedContainer.GetStatus())),
						helpers.String("completionStatus", string(watchedContainer.GetCompletionStatus())),
					)
				}
				return utils.ContainerReachedMaxTime
			}
		}
	}
}

func (cpm *ContainerProfileManager) saveProfile(watchedContainer *utils.WatchedContainerData, container *containercollection.Container) error {
	// Lock the container profile manager to prevent deleting the container profile while saving it
	if err := cpm.containerLocks.WithLockAndError(
		watchedContainer.ContainerID,
		func() error {
			return cpm.saveContainerProfile(watchedContainer, container)
		},
	); err != nil {
		if errors.Is(err, ErrContainerNotFound) {
			// Release the lock if the container is not found, as it might have been deleted
			cpm.containerLocks.ReleaseLock(watchedContainer.ContainerID)
		}

		return err
	}

	return nil

}

// saveContainerProfile saves the container profile to the storage
func (cpm *ContainerProfileManager) saveContainerProfile(watchedContainer *utils.WatchedContainerData, container *containercollection.Container) error {
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
			helpers.String("k8s workload", watchedContainer.K8sContainerID))
	}

	var containerData *containerData
	var ok bool
	if containerData, ok = cpm.containerIDToInfo.Load(watchedContainer.ContainerID); !ok {
		return ErrContainerNotFound
	}
	if containerData == nil {
		return ErrContainerNotFound
	}

	syscalls, err := cpm.syscallPeekFunc(watchedContainer.NsMntId)
	if err != nil {
		logger.L().Error("failed to peek syscalls for container", helpers.Error(err),
			helpers.String("containerID", watchedContainer.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
		)
	}

	// Update the timestamp of the last report (We do this before saving the profile to ensure the timestamp is always up-to-date)
	watchedContainer.PreviousReportTimestamp = watchedContainer.CurrentReportTimestamp
	watchedContainer.CurrentReportTimestamp = time.Now()

	containerProfile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: slug,
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
			Labels: utils.GetLabels(watchedContainer, false),
		},
		Spec: v1beta1.ContainerProfileSpec{
			Architectures:        []string{runtime.GOARCH},
			ImageID:              containerInfo.ImageID,
			ImageTag:             containerInfo.ImageTag,
			SeccompProfile:       seccompProfile,
			Capabilities:         containerData.getCapabilities(),
			Execs:                containerData.getExecs(),
			Opens:                containerData.getOpens(),
			Syscalls:             syscalls,
			Endpoints:            containerData.getEndpoints(),
			PolicyByRuleId:       containerData.getRulePolicies(),
			IdentifiedCallStacks: containerData.getCallStacks(),
			Egress:               containerData.getEgressNetworkNeighbors(container.K8s.Namespace, cpm.k8sClient, cpm.dnsResolverClient),
			Ingress:              containerData.getIngressNetworkNeighbors(container.K8s.Namespace, cpm.k8sClient, cpm.dnsResolverClient),
		},
	}

	if err := cpm.storageClient.CreateContainerProfile(containerProfile, container.K8s.Namespace); err != nil { // TODO: can this take time and block the goroutine? cuz we are under a lock here.
		// Empty the container data to prevent reporting the same data again
		containerData.emptyEvents()
		return err
	}

	logger.L().Debug("container profile saved successfully",
		helpers.String("containerID", watchedContainer.ContainerID),
		helpers.String("containerName", container.Runtime.ContainerName),
		helpers.String("podName", container.K8s.PodName),
	)

	// Empty the container data to prevent reporting the same data again
	containerData.emptyEvents()

	return nil
}
