package containerprofilemanager

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
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
		go cpm.deleteContainer(notif.Container)
	}
}

// addContainerWithTimeout handles adding a container with a timeout to prevent hanging
func (cpm *ContainerProfileManager) addContainerWithTimeout(container *containercollection.Container) {
	containerID := container.Runtime.ContainerID

	// Create container entry early with nil watchedContainerData
	entry := &ContainerEntry{
		data:  &containerData{},
		ready: make(chan struct{}),
	}
	cpm.addContainerEntry(containerID, entry)

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

	// Wait for shared container data with timeout
	sharedData, err := cpm.waitForSharedContainerData(containerID, ctx)
	if err != nil {
		// Remove the container entry and all stacked events if we fail
		cpm.removeContainerEntry(containerID)
		return fmt.Errorf("failed to get shared data for container %s: %w", containerID, err)
	}

	// Ignore ephemeral containers
	if sharedData.ContainerType == objectcache.EphemeralContainer {
		logger.L().Debug("ignoring ephemeral container",
			helpers.String("containerID", containerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
		cpm.removeContainerEntry(containerID)
		return nil
	}

	if sharedData.PreRunningContainer && !(cpm.cfg.EnableRuntimeDetection || cpm.cfg.EnablePartialProfileGeneration) {
		logger.L().Debug("ignoring pre-running container without runtime detection or partial profile generation",
			helpers.String("containerID", containerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
		cpm.removeContainerEntry(containerID)
		return nil
	}

	// Update the existing container entry with watchedContainerData
	entry, exists := cpm.getContainerEntry(containerID)
	if !exists || entry.data == nil {
		// Should not happen, but guard just in case
		return fmt.Errorf("container entry missing for %s after shared data ready", containerID)
	}
	entry.mu.Lock()
	entry.data.watchedContainerData = sharedData
	entry.mu.Unlock()

	// Set container data fields
	cpm.setContainerData(container, sharedData)

	// Setup monitoring timer
	sniffingTime := cpm.calculateSniffingTime(container)
	timer := time.AfterFunc(sniffingTime, func() {
		cpm.handleContainerMaxTime(container)
	})

	// Store timer in container data for cleanup
	entry.mu.Lock()
	entry.data.timer = timer
	entry.mu.Unlock()

	// Start monitoring in separate goroutine
	go cpm.startContainerMonitoring(container, sharedData)

	// Signal that the container entry is ready
	close(entry.ready)

	logger.L().Debug("container added to container profile manager",
		helpers.String("containerID", containerID),
		helpers.String("workloadID", sharedData.Wlid),
		helpers.String("containerName", container.Runtime.ContainerName),
		helpers.String("podName", container.K8s.PodName),
		helpers.String("namespace", container.K8s.Namespace))

	return nil
}

// calculateSniffingTime determines how long to monitor a container
func (cpm *ContainerProfileManager) calculateSniffingTime(container *containercollection.Container) time.Duration {
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

	return sniffingTime
}

// handleContainerMaxTime handles when a container reaches its maximum sniffing time
func (cpm *ContainerProfileManager) handleContainerMaxTime(container *containercollection.Container) {
	containerID := container.Runtime.ContainerID

	logger.L().Debug("reached max sniffing time for container",
		helpers.String("containerID", containerID),
		helpers.String("containerName", container.Runtime.ContainerName),
		helpers.String("podName", container.K8s.PodName),
		helpers.String("namespace", container.K8s.Namespace))

	var ackChan chan struct{}
	err := cpm.withContainerNoSizeUpdate(containerID, func(data *containerData) error {
		if data.watchedContainerData != nil {
			// Send container max time signal (blocking send, safe because monitoring goroutine is always running)
			data.watchedContainerData.SyncChannel <- ContainerReachedMaxTime
			ackChan = data.watchedContainerData.AckChan
		}
		return nil
	})

	if ackChan != nil {
		select {
		case <-ackChan:
			// Ack received
		case <-time.After(MaxWaitForAck):
			logger.L().Warning("timeout waiting for ack from monitoring goroutine after max time",
				helpers.String("containerID", containerID))
		}
	}

	if err == nil {
		cpm.deleteContainer(container)
		cpm.notifyContainerEndOfLife(container)
	}
}

// deleteContainer removes a container from the container profile manager
func (cpm *ContainerProfileManager) deleteContainer(container *containercollection.Container) {
	containerID := container.Runtime.ContainerID

	// Get the container entry
	entry, exists := cpm.getContainerEntry(containerID)
	if !exists {
		logger.L().Debug("container not found in container profile manager, skipping delete",
			helpers.String("containerID", containerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
		return
	}

	// Wait for shared data to be available, this is needed to avoid race condition in case the container is deleted before the shared data is available
	ctx, cancel := context.WithTimeout(context.Background(), MaxWaitForSharedContainerData)
	defer cancel()

	// Wait for either the container to be ready or timeout
	select {
	case <-entry.ready:
		// Container is ready, proceed with deletion
	case <-ctx.Done():
		logger.L().Debug("timeout waiting for container to be ready, proceeding with deletion",
			helpers.String("containerID", containerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}

	var ackChan chan struct{}
	// Clean up container resources
	entry.mu.Lock()
	if entry.data != nil {
		// Stop timer if still running
		if entry.data.timer != nil {
			entry.data.timer.Stop()
			entry.data.timer = nil
		}

		// Signal termination if monitoring is active
		if entry.data.watchedContainerData != nil &&
			entry.data.watchedContainerData.GetStatus() != objectcache.WatchedContainerStatusCompleted &&
			entry.data.watchedContainerData.GetStatus() != objectcache.WatchedContainerStatusTooLarge {

			// Set exit code based status if applicable
			if objectcache.GetTerminationExitCode(cpm.k8sObjectCache, container.K8s.Namespace,
				container.K8s.PodName, container.K8s.ContainerName, containerID) == 0 {
				entry.data.watchedContainerData.SetStatus(objectcache.WatchedContainerStatusCompleted)
			}

			// Send container termination signal (blocking send, safe because monitoring goroutine is always running)
			entry.data.watchedContainerData.SyncChannel <- ContainerHasTerminatedError
			ackChan = entry.data.watchedContainerData.AckChan
		}
	}
	entry.mu.Unlock()

	if ackChan != nil {
		select {
		case <-ackChan:
			// Ack received
		case <-time.After(MaxWaitForAck):
			logger.L().Warning("timeout waiting for ack from monitoring goroutine after termination",
				helpers.String("containerID", containerID))
		}
	}

	// Remove the container entry from the map
	cpm.removeContainerEntry(containerID)

	entry.mu.Lock()
	if entry.data != nil {
		entry.data = nil // Clear data to free resources
	}
	entry.mu.Unlock()

	logger.L().Debug("container deleted from container profile manager",
		helpers.String("containerID", containerID))
}

// startContainerMonitoring starts monitoring a container
func (cpm *ContainerProfileManager) startContainerMonitoring(container *containercollection.Container, sharedData *objectcache.WatchedContainerData) {
	if err := cpm.monitorContainer(container, sharedData); err != nil {
		logger.L().Info("stopped recording container profile",
			helpers.String("reason", err.Error()),
			helpers.String("containerID", container.Runtime.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}
}

// setContainerData sets the container data for the container profile manager
func (cpm *ContainerProfileManager) setContainerData(container *containercollection.Container, sharedData *objectcache.WatchedContainerData) {
	// Set completion status & status as soon as we start monitoring the container
	if sharedData.PreRunningContainer {
		sharedData.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusPartial)
	} else {
		sharedData.SetCompletionStatus(objectcache.WatchedContainerCompletionStatusFull)
	}
	sharedData.SetStatus(objectcache.WatchedContainerStatusInitializing)

	// Set series ID for the container
	if sharedData.SeriesID == "" {
		sharedData.SeriesID = createUUID()
	}

	// Set the sync channel
	if sharedData.SyncChannel == nil {
		sharedData.SyncChannel = make(chan error, 3) // 2 for (ContainerReachedMaxTime, ContainerHasTerminatedError) and 1 for queue errors
	}

	// Set the ack channel
	if sharedData.AckChan == nil {
		sharedData.AckChan = make(chan struct{}, 1) // 1 for (ContainerReachedMaxTime, ContainerHasTerminatedError)
	}

	// Set the update data ticker
	if sharedData.UpdateDataTicker == nil {
		sharedData.UpdateDataTicker = time.NewTicker(utils.AddJitter(cpm.cfg.InitialDelay, cpm.cfg.MaxJitterPercentage))
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

// waitForSharedContainerData waits for shared container data to be available
func (cpm *ContainerProfileManager) waitForSharedContainerData(containerID string, ctx context.Context) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(ctx, func() (*objectcache.WatchedContainerData, error) {
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

	cpm.notificationMu.Lock()
	defer cpm.notificationMu.Unlock()

	cpm.maxSniffTimeNotificationChan = append(cpm.maxSniffTimeNotificationChan, notificationChannel)
	logger.L().Debug("registered for container end of life notifications",
		helpers.Int("currentChannelCount", len(cpm.maxSniffTimeNotificationChan)))
}

// notifyContainerEndOfLife notifies all registered channels about the end of life
func (cpm *ContainerProfileManager) notifyContainerEndOfLife(container *containercollection.Container) {
	cpm.notificationMu.RLock()
	channels := make([]chan *containercollection.Container, len(cpm.maxSniffTimeNotificationChan))
	copy(channels, cpm.maxSniffTimeNotificationChan)
	cpm.notificationMu.RUnlock()

	for _, notifChan := range channels {
		select {
		case notifChan <- container:
		default:
			logger.L().Warning("notification channel for container end of life is full, skipping notification",
				helpers.String("containerID", container.Runtime.ContainerID),
				helpers.String("containerName", container.Runtime.ContainerName),
				helpers.String("podName", container.K8s.PodName),
				helpers.String("namespace", container.K8s.Namespace))
		}
	}
}
