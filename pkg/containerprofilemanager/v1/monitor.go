package containerprofilemanager

import (
	"errors"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
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
			cpm.saveProfile(watchedContainer, container.K8s.Namespace)

			// // save profile after initialaztion
			// if initOps != nil {
			// 	cpm.saveProfile(watchedContainer, container.K8s.Namespace, initOps)
			// 	initOps = nil
			// }

		case err := <-watchedContainer.SyncChannel:
			switch {
			case errors.Is(err, utils.ContainerHasTerminatedError):
				// If exit code is 0 we set the status to completed
				if objectcache.GetTerminationExitCode(cpm.k8sObjectCache, container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName, container.Runtime.ContainerID) == 0 {
					watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				}
				cpm.saveProfile(watchedContainer, container.K8s.Namespace)
				return err
			case errors.Is(err, utils.ContainerReachedMaxTime):
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				cpm.saveProfile(watchedContainer, container.K8s.Namespace)
				return err
			case errors.Is(err, utils.ObjectCompleted): // Todo figure out if we need this
				watchedContainer.SetStatus(utils.WatchedContainerStatusCompleted)
				return err
			case errors.Is(err, utils.TooLargeObjectError):
				logger.L().Debug("container profile manager: container is too large, stopping monitoring",
					helpers.String("containerID", container.Runtime.ContainerID),
					helpers.String("containerName", container.Runtime.ContainerName),
					helpers.String("podName", container.K8s.PodName),
					helpers.String("namespace", container.K8s.Namespace),
					helpers.String("container ID", container.Runtime.ContainerID),
				)
				watchedContainer.SetStatus(utils.WatchedContainerStatusTooLarge)
				return err
			}
		}
	}
}

func (cpm *ContainerProfileManager) saveProfile(watchedContainer *utils.WatchedContainerData, namespace string) error {
	// Lock the container profile manager to prevent deleting the container profile while saving it
	return cpm.containerLocks.WithLockAndError(
		watchedContainer.ContainerID,
		func() error {
			return cpm.saveContainerProfile(watchedContainer, namespace)
		},
	)
}

// saveContainerProfile saves the container profile to the object cache
func (cpm *ContainerProfileManager) saveContainerProfile(watchedContainer *utils.WatchedContainerData, namespace string) error {
	// TODO: implement saving logic
}
