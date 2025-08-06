package objectcache

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/kubescape/go-logger"
	loggerhelpers "github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

func UniqueName(namespace, name string) string {
	return namespace + "/" + name
}

func MetaUniqueName(obj metav1.Object) string {
	return UniqueName(obj.GetNamespace(), obj.GetName())
}

// list containerIDs from pod status
func ListContainersIDs(pod *corev1.Pod) []string {
	var containers []string

	for _, s := range pod.Status.ContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	for _, s := range pod.Status.InitContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	for _, s := range pod.Status.EphemeralContainerStatuses {
		containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
	}
	return containers
}

// list terminated containers from pod status
func ListTerminatedContainers(pod *corev1.Pod) []string {
	var containers []string

	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	for _, s := range pod.Status.InitContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	for _, s := range pod.Status.EphemeralContainerStatuses {
		if s.State.Terminated != nil {
			containers = append(containers, utils.TrimRuntimePrefix(s.ContainerID))
		}
	}
	return containers
}

// GetTerminationExitCode returns the termination exit code of the container, otherwise -1
func GetTerminationExitCode(k8sObjectsCache K8sObjectCache, namespace, podName, containerName, containerID string) int32 {
	notFoundError := fmt.Errorf("not found")
	backOff := backoff.NewExponentialBackOff()
	backOff.MaxInterval = 5 * time.Second
	maxElapsedTime := 30 * time.Second
	code, err := backoff.Retry(context.Background(), func() (int32, error) {
		podStatus := k8sObjectsCache.GetPodStatus(namespace, podName)
		if podStatus == nil {
			return 0, notFoundError
		}

		for _, s := range slices.Concat(podStatus.ContainerStatuses, podStatus.InitContainerStatuses, podStatus.EphemeralContainerStatuses) {
			if s.Name != containerName {
				continue
			}
			if s.State.Running != nil {
				return 0, notFoundError
			}
			states := []corev1.ContainerState{
				s.LastTerminationState, // for containers with restartPolicy Always
				s.State,                // for containers with restartPolicy Never
			}
			for _, state := range states {
				if state.Terminated != nil {
					// trim ID
					if containerID == utils.TrimRuntimePrefix(state.Terminated.ContainerID) {
						logger.L().Debug("GetTerminationExitCode - found exit code", loggerhelpers.Interface("code", state.Terminated.ExitCode), loggerhelpers.String("podName", podName), loggerhelpers.String("containerName", containerName), loggerhelpers.String("containerID", containerID))
						return state.Terminated.ExitCode, nil
					}
				}
			}
		}
		return 0, notFoundError
	}, backoff.WithBackOff(backOff), backoff.WithMaxElapsedTime(maxElapsedTime))
	if err != nil {
		logger.L().Debug("GetTerminationExitCode - couldn't find exit code", loggerhelpers.String("podName", podName), loggerhelpers.String("containerName", containerName), loggerhelpers.String("containerID", containerID))
		return int32(-1)
	}

	return code
}
