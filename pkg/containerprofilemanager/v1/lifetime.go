package containerprofilemanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ContainerCallback handles container lifecycle events
func (cpm *ContainerProfileManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if cpm.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go cpm.addContainerWithTimeout(notif.Container)
	case containercollection.EventTypeRemoveContainer:
		if cpm.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go cpm.deleteContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainerWithTimeout handles adding a container with a timeout to prevent hanging
func (cpm *ContainerProfileManager) addContainerWithTimeout(container *containercollection.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxWaitForSharedContainerData)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- cpm.addContainer(container, ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.L().Error("failed to add container to the container profile manager", helpers.Error(err))
		}
	case <-ctx.Done():
		logger.L().Error("timeout while adding container to the container profile manager",
			helpers.String("containerID", container.Runtime.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}
}

// addContainer adds a container to the container profile manager
func (cpm *ContainerProfileManager) addContainer(container *containercollection.Container, ctx context.Context) error {
	containerID := container.Runtime.ContainerID

	// Check if Pod has a label of max sniffing time
	sniffingTime := utils.AddJitter(cpm.cfg.MaxSniffingTime, cpm.cfg.MaxJitterPercentage)
	if podLabelMaxSniffingTime, ok := container.K8s.PodLabels[MaxSniffingTimeLabel]; ok {
		if duration, err := time.ParseDuration(podLabelMaxSniffingTime); err == nil {
			sniffingTime = duration
		} else {
			logger.L().Debug("failed to parse pod label for max sniffing time",
				helpers.String("podName", container.K8s.PodName),
				helpers.String("namespace", container.K8s.Namespace),
				helpers.String("podLabelMaxSniffingTime", podLabelMaxSniffingTime),
				helpers.Error(err))
		}
	}

	time.AfterFunc(sniffingTime, func() { // TODO: use the timer returned to cancel the timer if the container is deleted before it expires
		logger.L().Debug("reached max sniffing time for container",
			helpers.String("containerID", containerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
		err := cpm.containerLocks.WithLockAndError(containerID, func() error {
			if containerData, ok := cpm.containerIDToInfo.Load(containerID); ok {
				containerData.watchedContainerData.SyncChannel <- utils.ContainerReachedMaxTime
				return nil
			}
			return ErrContainerNotFound
		})
		if err != nil && errors.Is(err, ErrContainerNotFound) {
			cpm.containerLocks.ReleaseLock(containerID) // Release the lock if we failed to send the signal
			return
		}
		time.Sleep(100 * time.Millisecond) // Give some time for the monitoring goroutine to process the signal (TODO: find a better way to handle this).
		cpm.deleteContainer(containerID)
		// Notify all registered channels about the end of life (in cases where runtime detection is not used we can stop sniffing).
		// TODO: Register to this from the container watcher.
		for _, notifChan := range cpm.maxSniffTimeNotificationChan {
			select {
			case notifChan <- container:
			default:
				logger.L().Warning("notification channel for container end of life is full, skipping notification",
					helpers.String("containerID", containerID),
					helpers.String("containerName", container.Runtime.ContainerName),
					helpers.String("podName", container.K8s.PodName),
					helpers.String("namespace", container.K8s.Namespace))
			}
		}
	})

	return cpm.containerLocks.WithLockAndError(containerID, func() error {
		// Get shared container data
		sharedData, err := cpm.waitForSharedContainerData(containerID, ctx)
		if err != nil {
			logger.L().Error("failed to get shared data for container",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		if !cpm.cfg.EnableRuntimeDetection && sharedData.PreRunningContainer {
			logger.L().Debug("ignoring pre-running container without runtime detection",
				helpers.String("containerID", containerID),
				helpers.String("containerName", container.Runtime.ContainerName),
				helpers.String("podName", container.K8s.PodName),
				helpers.String("namespace", container.K8s.Namespace),
				helpers.String("container ID", container.Runtime.ContainerID),
			)
			return nil
		}

		// Set container data
		cpm.setContainerData(container, sharedData)

		// Add to container info map
		cpm.containerIDToInfo.Set(containerID, &containerData{
			watchedContainerData: sharedData,
		})

		// Start monitoring the container (separate goroutine because we don't want to block the callback)
		go cpm.startContainerMonitoring(container, sharedData)

		logger.L().Debug("container added to container profile manager",
			helpers.String("containerID", containerID),
			helpers.String("workloadID", sharedData.Wlid),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))

		return nil
	})
}

// startContainerMonitoring starts monitoring a container
func (cpm *ContainerProfileManager) startContainerMonitoring(container *containercollection.Container, sharedData *utils.WatchedContainerData) {
	if err := cpm.monitorContainer(container, sharedData); err != nil {
		logger.L().Info("stopped recording container profile", helpers.String("reason", err.Error()),
			helpers.String("containerID", container.Runtime.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}
}

// setContainerData sets the container data for the container profile manager
func (cpm *ContainerProfileManager) setContainerData(container *containercollection.Container, sharedData *utils.WatchedContainerData) {
	// Set completion status & status as soon as we start monitoring the container
	if sharedData.PreRunningContainer {
		sharedData.SetCompletionStatus(utils.WatchedContainerCompletionStatusPartial)
	} else {
		sharedData.SetCompletionStatus(utils.WatchedContainerCompletionStatusFull)
	}
	sharedData.SetStatus(utils.WatchedContainerStatusInitializing)

	// Set series ID for the container
	if sharedData.SeriesID == "" {
		sharedData.SeriesID = createUUID()
	}

	// Set the sync channel
	if sharedData.SyncChannel == nil {
		sharedData.SyncChannel = make(chan error, 10)
	}

	// Set the update data ticker
	if sharedData.UpdateDataTicker == nil {
		sharedData.UpdateDataTicker = time.NewTicker(utils.AddJitter(cpm.cfg.UpdateDataPeriod, cpm.cfg.MaxJitterPercentage))
	}

	// Set the initial delay expired to false
	sharedData.InitialDelayExpired = false

	// Set the container id
	if sharedData.ContainerID == "" {
		sharedData.ContainerID = container.Runtime.ContainerID
	}
	// Set the mount namespace ID
	if sharedData.NsMntId == 0 {
		sharedData.NsMntId = container.Mntns
	}
}

// deleteContainer deletes a container from the container profile manager
func (cpm *ContainerProfileManager) deleteContainer(containerID string) {
	var containerData *containerData
	var ok bool
	// Check if the container is being monitored
	if containerData, ok = cpm.containerIDToInfo.Load(containerID); !ok {
		logger.L().Debug("container not found in container profile manager, skipping delete",
			helpers.String("containerID", containerID))
		return
	}
	// Send container termination signal to the sync channel
	containerData.watchedContainerData.SyncChannel <- utils.ContainerHasTerminatedError

	// Wait a bit to allow the monitoring goroutine to finish (it will take a lock on the container ID)
	// This is a workaround to ensure that the monitoring goroutine has enough time to process the signal
	time.Sleep(100 * time.Millisecond)

	cpm.containerLocks.WithLock(containerID, func() { // Clean up container info
		cpm.containerIDToInfo.Delete(containerID)
		logger.L().Debug("container deleted from container profile manager",
			helpers.String("containerID", containerID))
	})

	// Clean up the lock when done - call this outside the WithLock closure
	cpm.containerLocks.ReleaseLock(containerID)
}

// waitForSharedContainerData waits for shared container data to be available
func (cpm *ContainerProfileManager) waitForSharedContainerData(containerID string, ctx context.Context) (*utils.WatchedContainerData, error) {
	return backoff.Retry(ctx, func() (*utils.WatchedContainerData, error) {
		if sharedData := cpm.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// RegisterForContainerEndOfLife registers a channel to receive notifications when a container reaches its max sniffing time
func (cpm *ContainerProfileManager) RegisterForContainerEndOfLife(notificationChannel chan *containercollection.Container) {
	if notificationChannel == nil {
		logger.L().Error("nil channel provided for container end of life notifications")
		return
	}
	cpm.maxSniffTimeNotificationChan = append(cpm.maxSniffTimeNotificationChan, notificationChannel)
	logger.L().Debug("registered for container end of life notifications",
		helpers.Int("currentChannelCount", len(cpm.maxSniffTimeNotificationChan)))
}
