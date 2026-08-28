package rulemanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	backoffv5 "github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/contextdetection/detectors"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
)

// monitorContainer blocks for the lifetime of one container registration. It
// exits only in response to rm.ctx being cancelled (process shutdown) or to
// done being closed by the specific ContainerCallback removal that created
// it. It intentionally does not re-derive liveness by polling shared mutable
// state (e.g. rm.trackedContainers) on a timer: a container ID that is
// removed and re-added faster than a poll interval would look "tracked
// again" to a stale goroutine from the earlier registration, letting it
// survive alongside the new one. done is scoped per-registration so only the
// registration that owns it is ever told to stop.
func (rm *RuleManager) monitorContainer(container *containercollection.Container, k8sContainerID string, done <-chan struct{}) error {
	logger.L().Debug("RuleManager - start monitor on container",
		helpers.String("container ID", container.Runtime.ContainerID),
		helpers.String("k8s container id", k8sContainerID))

	select {
	case <-rm.ctx.Done():
		logger.L().Debug("RuleManager - stop monitor on container",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s container id", k8sContainerID))
		return nil
	case <-done:
		logger.L().Debug("RuleManager - container is not tracked",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("k8s container id", k8sContainerID))
		return nil
	}
}

func (rm *RuleManager) ContainerCallback(notif containercollection.PubSubEvent) {
	// check if the container should be ignored
	if rm.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Debug("RuleManager - add container",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))

		if rm.trackedContainers.Contains(k8sContainerID) {
			logger.L().Debug("RuleManager - container already exist in memory",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID))
			return
		}

		// Detect context and add to the registry
		contextInfo, err := rm.detectorManager.DetectContext(notif.Container)
		if err != nil {
			logger.L().Warning("RuleManager - failed to detect context, defaulting to standalone",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.Error(err))
			contextInfo = &detectors.StandaloneContextInfo{
				ContainerID:   notif.Container.Runtime.ContainerID,
				ContainerName: notif.Container.Runtime.ContainerName,
			}
		}

		if contextInfo != nil && notif.Container.Mntns != 0 {
			if err := rm.mntnsRegistry.Register(notif.Container.Mntns, contextInfo); err != nil {
				logger.L().Warning("RuleManager - failed to register in mntns registry",
					helpers.String("container ID", notif.Container.Runtime.ContainerID),
					helpers.Error(err))
			}
		}

		rm.trackedContainers.Add(k8sContainerID)
		done := make(chan struct{})
		rm.trackedContainerDone.Set(k8sContainerID, done)
		shim, err := utils.GetProcessStat(int(notif.Container.ContainerPid()))
		if err != nil {
			logger.L().Warning("RuleManager - failed to get shim process", helpers.Error(err))
		} else {
			rm.containerIdToShimPid.Set(notif.Container.Runtime.ContainerID, uint32(shim.PPID))
		}
		rm.containerIdToPid.Set(notif.Container.Runtime.ContainerID, notif.Container.ContainerPid())
		go rm.startRuleManager(notif.Container, k8sContainerID, done)
	case containercollection.EventTypeRemoveContainer:
		logger.L().Debug("RuleManager - remove container",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))

		if notif.Container.Mntns != 0 {
			rm.mntnsRegistry.Unregister(notif.Container.Mntns)
		}

		rm.trackedContainers.Remove(k8sContainerID)
		if done, ok := rm.trackedContainerDone.Load(k8sContainerID); ok {
			close(done)
			rm.trackedContainerDone.Delete(k8sContainerID)
		}

		// Reclaim immediately rather than waiting for TTL: a churning node would
		// otherwise hold markers for containers that no longer exist.
		//
		// This uses Runtime.ContainerID verbatim because that is exactly what the
		// write path stored under -- EnrichedEvent.ContainerID is assigned from
		// container.Runtime.ContainerID (containercallback.go), untrimmed. Do NOT
		// pass it through utils.TrimRuntimePrefix: that helper returns "" for an ID
		// with no "//" separator, and ContainerScopeID("") is the HOST bucket, so
		// trimming here would purge every host process marker on each container
		// exit.
		if rm.stateStore != nil {
			rm.stateStore.PurgeScope(rulestate.ContainerScopeID(notif.Container.Runtime.ContainerID))
		}

		namespace := notif.Container.K8s.Namespace
		podName := notif.Container.K8s.PodName
		podID := utils.CreateK8sPodID(namespace, podName)

		time.AfterFunc(10*time.Minute, func() {
			if rm.podStillTracked(namespace, podName) {
				logger.L().Debug("RuleManager - keeping pod in podToWlid map due to active containers",
					helpers.String("podID", podID))
				return
			}
			logger.L().Debug("RuleManager - removing pod from podToWlid map",
				helpers.String("podID", podID))
			rm.podToWlid.Delete(podID)
			rm.purgePodScopeIfPodGone(namespace, podName)
		})

		rm.containerIdToShimPid.Delete(notif.Container.Runtime.ContainerID)
		rm.containerIdToPid.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (rm *RuleManager) waitForSharedContainerData(containerID string) (*objectcache.WatchedContainerData, error) {
	return backoffv5.Retry(context.Background(), func() (*objectcache.WatchedContainerData, error) {
		if sharedData := rm.objectCache.K8sObjectCache().GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoffv5.WithBackOff(backoffv5.NewExponentialBackOff()))
}

// podStillTracked reports whether any container of this pod is still tracked.
// A pod's identity spans its containers, so pod-level cleanup can only run once
// the last of them is gone.
func (rm *RuleManager) podStillTracked(namespace, podName string) bool {
	stillTracked := false
	rm.trackedContainers.Each(func(id string) bool {
		// Parse the container ID to reliably extract the pod info
		parts := strings.Split(id, "/")
		if len(parts) == 3 && parts[0] == namespace && parts[1] == podName {
			stillTracked = true
			return true // We found a match, can stop iteration
		}
		return false // No match yet, continue looking
	})
	return stillTracked
}

// purgePodScopeIfPodGone reclaims a dead pod's state.
//
// Container scope is purged the moment a container goes, but pod scope outlives
// any single container by design, so it can only be reclaimed once the pod's LAST
// container has gone -- purging earlier would cut a correlation chain that is
// still legitimately in progress across a surviving sibling. Without this the
// bucket survived until TTL, and on a churning node many dead pods' worth of
// entries counted against the global ceiling at once.
func (rm *RuleManager) purgePodScopeIfPodGone(namespace, podName string) {
	if rm.stateStore == nil || rm.podStillTracked(namespace, podName) {
		return
	}
	rm.stateStore.PurgeScope(rulestate.PodScopeID(namespace, podName))
}
