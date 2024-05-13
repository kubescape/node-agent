package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"path/filepath"
	"slices"
	"strings"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func getExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		return event.Args[0]
	}
	return event.Comm
}

func getExecFullPathFromEvent(event *tracerexectype.Event) string {
	execPath := getExecPathFromEvent(event)
	if strings.HasPrefix(execPath, "./") || strings.HasPrefix(execPath, "../") {
		execPath = filepath.Join(event.Cwd, execPath)
	} else if !strings.HasPrefix(execPath, "/") {
		execPath = "/" + execPath
	}
	return execPath
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
	for i := range ap.Spec.EphemeralContainers {
		if ap.Spec.EphemeralContainers[i].Name == containerName {
			return ap.Spec.EphemeralContainers[i], nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, fmt.Errorf("container %s not found in application profile", containerName)
}

func getContainerFromNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, containerName string) (v1beta1.NetworkNeighborhoodContainer, error) {
	for i := range nn.Spec.Containers {
		if nn.Spec.Containers[i].Name == containerName {
			return nn.Spec.Containers[i], nil
		}
	}
	for i := range nn.Spec.InitContainers {
		if nn.Spec.InitContainers[i].Name == containerName {
			return nn.Spec.InitContainers[i], nil
		}
	}
	for i := range nn.Spec.EphemeralContainers {
		if nn.Spec.EphemeralContainers[i].Name == containerName {
			return nn.Spec.EphemeralContainers[i], nil
		}
	}
	return v1beta1.NetworkNeighborhoodContainer{}, fmt.Errorf("container %s not found in network neighborhood profile", containerName)
}

func getContainerMountPaths(namespace, podName, containerName string, k8sObjCache objectcache.K8sObjectCache) ([]string, error) {
	podSpec := k8sObjCache.GetPodSpec(namespace, podName)
	if podSpec == nil {
		return []string{}, fmt.Errorf("pod spec not available for %s/%s", namespace, podName)
	}

	mountPaths := []string{}
	for _, container := range podSpec.Containers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.InitContainers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.EphemeralContainers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	return mountPaths, nil
}

func isExecEventWhitelisted(execEvent *tracerexectype.Event, objectCache objectcache.ObjectCache, compareArgs bool) (bool, error) {
	// Check if the exec is whitelisted, if so, return nil
	execPath := getExecPathFromEvent(execEvent)

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
	if ap == nil {
		return false, fmt.Errorf("application profile not found for container %s", execEvent.Runtime.ContainerID)
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return false, fmt.Errorf("container %s not found in application profile", execEvent.GetContainer())
	}

	for _, exec := range appProfileExecList.Execs {
		if exec.Path == execPath {
			// Either compare args false or args match
			if !compareArgs || slices.Compare(exec.Args, execEvent.Args) == 0 {
				return true, nil
			}
		}
	}
	return false, nil
}
