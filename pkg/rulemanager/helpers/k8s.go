package helpers

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

func getContainerMountPaths(namespace, podName, containerName string, k8sObjCache objectcache.K8sObjectCache) ([]string, error) {
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

func getContainerMountPathsOverload(h *Helpers) cel.EnvOption {
	return cel.Function("get_container_mount_paths", cel.Overload(
		"get_container_mount_paths_string_string_string",
		[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
		cel.ListType(cel.StringType),
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			namespace := string(args[0].(types.String))
			podName := string(args[1].(types.String))
			containerName := string(args[2].(types.String))
			if h.objectCache == nil {
				return types.NewErr("object cache is nil")
			}
			mountPaths, err := getContainerMountPaths(namespace, podName, containerName, h.objectCache.K8sObjectCache())
			if err != nil {
				return types.NewErr("failed to get container mount paths: %v", err)
			}
			return types.NewDynamicList(types.DefaultTypeAdapter, mountPaths)
		})))
}
