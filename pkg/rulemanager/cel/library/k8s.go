package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

func K8s(k8sObjCache objectcache.K8sObjectCache) cel.EnvOption {
	return cel.Lib(&k8sLibrary{k8sObjCache: k8sObjCache})
}

type k8sLibrary struct {
	k8sObjCache objectcache.K8sObjectCache
}

func (l *k8sLibrary) LibraryName() string {
	return "k8s"
}

func (l *k8sLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *k8sLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"get_container_mount_paths": {
			cel.Overload(
				"k8s_get_container_mount_paths", []*cel.Type{cel.StringType, cel.StringType, cel.StringType}, cel.ListType(cel.StringType),
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					return l.getContainerMountPaths(values[0], values[1], values[2])
				}),
			),
		},
	}
}

func (l *k8sLibrary) getContainerMountPaths(namespace, podName, containerName ref.Val) ref.Val {
	if l.k8sObjCache == nil {
		return types.NewErr("k8sObjCache is nil")
	}

	namespaceStr, ok := namespace.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(namespace)
	}
	podNameStr, ok := podName.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(podName)
	}
	containerNameStr, ok := containerName.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerName)
	}

	podSpec := l.k8sObjCache.GetPodSpec(namespaceStr, podNameStr)
	if podSpec == nil {
		return types.NewErr("pod spec not available for %s/%s", namespaceStr, podNameStr)
	}

	var mountPaths []string
	for _, container := range podSpec.Containers {
		if container.Name == containerNameStr {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.InitContainers {
		if container.Name == containerNameStr {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.EphemeralContainers {
		if container.Name == containerNameStr {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	return types.NewDynamicList(types.DefaultTypeAdapter, mountPaths)
}

func (l *k8sLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *k8sLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

var _ Library = (*k8sLibrary)(nil)
