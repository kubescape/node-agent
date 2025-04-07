package ruleengine

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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

func IsExecEventInProfile(execEvent *events.ExecEvent, objectCache objectcache.ObjectCache, compareArgs bool) (bool, error) {
	// Check if the exec is whitelisted, if so, return nil
	execPath := GetExecPathFromEvent(execEvent)

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
	if ap == nil {
		return false, ProfileNotFound
	}

	appProfileExecList, err := GetContainerFromApplicationProfile(ap, execEvent.GetContainer())
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

func IsAllowed(event *eventtypes.Event, objCache objectcache.ObjectCache, process string, ruleId string) (bool, error) {
	if objCache == nil {
		return false, nil
	}
	ap := objCache.ApplicationProfileCache().GetApplicationProfile(event.Runtime.ContainerID)
	if ap == nil {
		return false, errors.New("application profile not found")
	}

	appProfile, err := GetContainerFromApplicationProfile(ap, event.GetContainer())
	if err != nil {
		return false, err
	}

	// rule policy does not exists, allowed by default
	if _, ok := appProfile.PolicyByRuleId[ruleId]; !ok {
		return true, nil
	}

	if policy, ok := appProfile.PolicyByRuleId[ruleId]; ok {
		if policy.AllowedContainer || slices.Contains(policy.AllowedProcesses, process) {
			logger.L().Debug("isAllowed - process is allowed by policy", helpers.String("ruleID", ruleId), helpers.String("process", process))
			return true, nil
		}
	}

	logger.L().Debug("isAllowed - process is not allowed by policy", helpers.String("ruleID", ruleId), helpers.String("process", process))
	return false, nil
}
