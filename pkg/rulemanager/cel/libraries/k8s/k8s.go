package k8s

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func New(k8sObjCache objectcache.K8sObjectCache, config config.Config) libraries.Library {
	return &k8sLibrary{
		k8sObjCache: k8sObjCache,
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
}

func K8s(k8sObjCache objectcache.K8sObjectCache, config config.Config) cel.EnvOption {
	return cel.Lib(New(k8sObjCache, config))
}

type k8sLibrary struct {
	k8sObjCache   objectcache.K8sObjectCache
	functionCache *cache.FunctionCache
}

func (l *k8sLibrary) LibraryName() string {
	return "k8s"
}

func (l *k8sLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *k8sLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"k8s.get_container_mount_paths": {
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
		"k8s.is_api_server_address": {
			cel.Overload(
				"k8s_is_api_server_address", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 1 {
						return types.NewErr("expected 1 argument, got %d", len(values))
					}
					return l.isApiServerAddress(values[0])
				}),
			),
		},
		"k8s.get_container_by_name": {
			cel.Overload(
				"k8s_get_container_by_name", []*cel.Type{cel.StringType, cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					return l.getContainerByName(values[0], values[1], values[2])
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

func (l *k8sLibrary) isApiServerAddress(address ref.Val) ref.Val {
	if l.k8sObjCache == nil {
		return types.NewErr("k8sObjCache is nil")
	}

	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}

	apiServerAddress := l.k8sObjCache.GetApiServerIpAddress()
	if apiServerAddress == "" {
		return types.Bool(false)
	}

	return types.Bool(addressStr == apiServerAddress)
}

func (l *k8sLibrary) getContainerByName(namespace, podName, containerName ref.Val) ref.Val {
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
		return types.Bool(false)
	}

	// Check regular containers
	for _, container := range podSpec.Containers {
		if container.Name == containerNameStr {
			return types.Bool(true)
		}
	}

	// Check init containers
	for _, container := range podSpec.InitContainers {
		if container.Name == containerNameStr {
			return types.Bool(true)
		}
	}

	// Check ephemeral containers
	for _, container := range podSpec.EphemeralContainers {
		if container.Name == containerNameStr {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
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

func (l *k8sLibrary) CostEstimator() checker.CostEstimator {
	return &k8sCostEstimator{}
}

// k8sCostEstimator implements the checker.CostEstimator for the 'k8s' library.
type k8sCostEstimator struct{}

func (e *k8sCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "k8s.get_container_mount_paths":
		// Cache lookup + O(n) search through 3 container types + O(m) volume mount iteration
		cost = 25
	case "k8s.is_api_server_address":
		// Cache lookup + simple string comparison - O(1)
		cost = 5
	case "k8s.get_container_by_name":
		// Cache lookup + O(n) search through 3 container types by name
		cost = 15
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *k8sCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*k8sCostEstimator)(nil)
var _ libraries.Library = (*k8sLibrary)(nil)
