package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func getExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		return event.Args[0]
	}
	return event.Comm
}
func getContainerFromApplicationProfile(ap *v1beta1.ApplicationProfile, containerName string) (v1beta1.ApplicationProfileContainer, error) {
	for i := range ap.Spec.Containers {
		if ap.Spec.Containers[i].Name == containerName {
			return ap.Spec.Containers[i], nil
		}
	}
	for i := range ap.Spec.InitContainers {
		if ap.Spec.InitContainers[i].Name == containerName {
			return ap.Spec.InitContainers[i], nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, fmt.Errorf("container %s not found in application profile", containerName)
}

func getContainerMountPaths(namespace, podName, containerName string, k8sProvider ruleengine.K8sObjectProvider) ([]string, error) {
	podSpec, err := k8sProvider.GetPodSpec(namespace, podName)
	if err != nil {
		return []string{}, fmt.Errorf("failed to get pod spec: %v", err)
	}

	mountPaths := []string{}
	for _, container := range podSpec.Containers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	return mountPaths, nil
}
