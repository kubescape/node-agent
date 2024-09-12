package ruleengine

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

// SensitiveFiles is a list of sensitive files that should not be accessed by the application unexpectedly.
var SensitiveFiles = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_config",
	"/etc/pam.d",
}

var (
	ContainerNotFound = errors.New("container not found")
	ProfileNotFound   = errors.New("application profile not found")
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
	return v1beta1.ApplicationProfileContainer{}, ContainerNotFound
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
	return v1beta1.NetworkNeighborhoodContainer{}, ContainerNotFound
}

func getContainerMountPaths(namespace, podName, containerName string, k8sObjCache objectcache.K8sObjectCache) ([]string, error) {
	podSpec := k8sObjCache.GetPodSpec(namespace, podName)
	if podSpec == nil {
		return []string{}, fmt.Errorf("pod spec not available for %s/%s", namespace, podName)
	}

	var mountPaths []string
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

func isExecEventInProfile(execEvent *tracerexectype.Event, objectCache objectcache.ObjectCache, compareArgs bool) (bool, error) {
	// Check if the exec is whitelisted, if so, return nil
	execPath := getExecPathFromEvent(execEvent)

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
	if ap == nil {
		return false, ProfileNotFound
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return false, ContainerNotFound
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

func interfaceToStringSlice(val interface{}) ([]string, bool) {
	sliceOfInterfaces, ok := val.([]interface{})
	if ok {
		sliceOfStrings := []string{}
		for _, interfaceVal := range sliceOfInterfaces {
			sliceOfStrings = append(sliceOfStrings, fmt.Sprintf("%v", interfaceVal))
		}
		return sliceOfStrings, true
	}
	return nil, false
}

func CompareDynamic(dynamicPath, regularPath string) (string, bool) {

	dynamicSegments := strings.Split(dynamicPath, "/")
	regularSegments := strings.Split(regularPath, "/")

	if len(dynamicSegments) != len(regularSegments) {
		return regularPath, false
	}

	modified := false
	for i := range dynamicSegments {
		if dynamicSegments[i] == dynamicpathdetector.DynamicIdentifier {
			if !modified {
				regularSegments[i] = dynamicpathdetector.DynamicIdentifier
				modified = true
			}
		} else if dynamicSegments[i] != regularSegments[i] {
			return regularPath, false
		}
	}

	if modified {
		return strings.Join(regularSegments, "/"), true
	}

	return regularPath, dynamicPath == regularPath
}
