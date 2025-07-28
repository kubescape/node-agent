package rulemanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	backoffv5 "github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

func (rm *RuleManager) monitorContainer(container *containercollection.Container, k8sContainerID string) error {
	logger.L().Debug("RuleManager - start monitor on container",
		helpers.String("container ID", container.Runtime.ContainerID),
		helpers.String("k8s container id", k8sContainerID))

	syscallTicker := time.NewTicker(syscallPeriod)

	for {
		select {
		case <-rm.ctx.Done():
			logger.L().Debug("RuleManager - stop monitor on container",
				helpers.String("container ID", container.Runtime.ContainerID),
				helpers.String("k8s container id", k8sContainerID))
			return nil
		case <-syscallTicker.C:
			if rm.syscallPeekFunc == nil {
				logger.L().Debug("RuleManager - syscallPeekFunc is not set", helpers.String("container ID", container.Runtime.ContainerID))
				continue
			}

			if container.Mntns == 0 {
				logger.L().Debug("RuleManager - mount namespace ID is not set", helpers.String("container ID", container.Runtime.ContainerID))
			}

			if !rm.trackedContainers.Contains(k8sContainerID) {
				logger.L().Debug("RuleManager - container is not tracked", helpers.String("container ID", container.Runtime.ContainerID))
				return nil
			}

			var syscalls []string
			if syscallsFromFunc, err := rm.syscallPeekFunc(container.Mntns); err == nil {
				syscalls = syscallsFromFunc
			}

			if len(syscalls) == 0 {
				continue
			}

			for _, syscall := range syscalls {
				event := types.SyscallEvent{
					Event: eventtypes.Event{
						Timestamp: eventtypes.Time(time.Now().UnixNano()),
						Type:      eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: container.Runtime.ContainerID,
								RuntimeName: container.Runtime.RuntimeName,
							},
							K8s: eventtypes.K8sMetadata{
								Node: rm.nodeName,
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									Namespace:     container.K8s.Namespace,
									PodName:       container.K8s.PodName,
									PodLabels:     container.K8s.PodLabels,
									ContainerName: container.K8s.ContainerName,
								},
							},
						},
					},
					WithMountNsID: eventtypes.WithMountNsID{
						MountNsID: container.Mntns,
					},
					Pid: container.ContainerPid(),
					// TODO: Figure out how to get UID, GID and comm from the syscall.
					// Uid:         container.OciConfig.Process.User.UID,
					// Gid:         container.OciConfig.Process.User.GID,
					// Comm:        container.OciConfig.Process.Args[0],
					SyscallName: syscall,
				}

				tree, err := rm.processManager.GetContainerProcessTree(container.Runtime.ContainerID, event.Pid, true)
				if err != nil {
					process := apitypes.Process{
						PID: event.Pid,
					}
					tree, err = utils.CreateProcessTree(&process,
						rm.containerIdToShimPid.Get(container.Runtime.ContainerID))
					if err != nil {
						logger.L().Error("RuleManager - failed to create process tree fallback", helpers.Error(err))
						tree, err = rm.processManager.GetContainerProcessTree(container.Runtime.ContainerID, event.Pid, true)
						if err != nil {
							logger.L().Error("RuleManager - failed to create process tree fallback", helpers.Error(err))
							continue
						}
					}
				}

				rm.ReportEnrichedEvent(&events.EnrichedEvent{
					EventType:   utils.SyscallEventType,
					ContainerID: container.Runtime.ContainerID,
					ProcessTree: tree,
				})

			}
		}
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

		rm.trackedContainers.Add(k8sContainerID)
		shim, err := utils.GetProcessStat(int(notif.Container.ContainerPid()))
		if err != nil {
			logger.L().Warning("RuleManager - failed to get shim process", helpers.Error(err))
		} else {
			rm.containerIdToShimPid.Set(notif.Container.Runtime.ContainerID, uint32(shim.PPID))
		}
		rm.containerIdToPid.Set(notif.Container.Runtime.ContainerID, notif.Container.ContainerPid())
		go rm.startRuleManager(notif.Container, k8sContainerID)
	case containercollection.EventTypeRemoveContainer:
		logger.L().Debug("RuleManager - remove container",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))

		rm.trackedContainers.Remove(k8sContainerID)
		namespace := notif.Container.K8s.Namespace
		podName := notif.Container.K8s.PodName
		podID := utils.CreateK8sPodID(namespace, podName)

		time.AfterFunc(10*time.Minute, func() {
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

			if !stillTracked {
				logger.L().Debug("RuleManager - removing pod from podToWlid map",
					helpers.String("podID", podID))
				rm.podToWlid.Delete(podID)
			} else {
				logger.L().Debug("RuleManager - keeping pod in podToWlid map due to active containers",
					helpers.String("podID", podID))
			}
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
