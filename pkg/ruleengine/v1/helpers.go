package ruleengine

import (
	"crypto/md5"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"

	"github.com/kubescape/node-agent/pkg/objectcache"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// SensitiveFiles is a list of sensitive files that should not be accessed by the application unexpectedly.
var SensitiveFiles = []string{
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh/ssh_config",
	"/etc/ssh/sshd_config",
}

var (
	ContainerNotFound = errors.New("container not found")
	ProfileNotFound   = errors.New("application profile not found")
)

func GetExecPathFromEvent(event *events.ExecEvent) string {
	if len(event.Args) > 0 {
		if event.Args[0] != "" {
			return event.Args[0]
		}
	}
	return event.Comm
}

func GetExecFullPathFromEvent(event *events.ExecEvent) string {
	execPath := GetExecPathFromEvent(event)
	if strings.HasPrefix(execPath, "./") || strings.HasPrefix(execPath, "../") {
		execPath = filepath.Join(event.Cwd, execPath)
	} else if !strings.HasPrefix(execPath, "/") {
		execPath = "/" + execPath
	}
	return execPath
}

func GetContainerFromApplicationProfile(ap *v1beta1.ApplicationProfile, containerName string) (v1beta1.ApplicationProfileContainer, error) {
	for _, s := range ap.Spec.Containers {
		if s.Name == containerName {
			return s, nil
		}
	}
	for _, s := range ap.Spec.InitContainers {
		if s.Name == containerName {
			return s, nil
		}
	}
	for _, s := range ap.Spec.EphemeralContainers {
		if s.Name == containerName {
			return s, nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, ContainerNotFound
}

func GetContainerFromNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood, containerName string) (v1beta1.NetworkNeighborhoodContainer, error) {
	for _, c := range nn.Spec.Containers {
		if c.Name == containerName {
			return c, nil
		}
	}
	for _, c := range nn.Spec.InitContainers {
		if c.Name == containerName {
			return c, nil
		}
	}
	for _, c := range nn.Spec.EphemeralContainers {
		if c.Name == containerName {
			return c, nil
		}
	}
	return v1beta1.NetworkNeighborhoodContainer{}, ContainerNotFound
}

func GetContainerMountPaths(namespace, podName, containerName string, k8sObjCache objectcache.K8sObjectCache) ([]string, error) {
	if k8sObjCache == nil {
		return []string{}, fmt.Errorf("k8sObjCache is nil")
	}

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

func InterfaceToStringSlice(val interface{}) ([]string, bool) {
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

func HashStringToMD5(str string) string {
	// Create an md5 hash of the string
	hash := md5.Sum([]byte(str))
	// Convert the hash to a hexadecimal string
	hashString := fmt.Sprintf("%x", hash)
	// Return the hash string
	return hashString
}
