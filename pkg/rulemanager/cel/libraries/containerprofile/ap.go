package containerprofile

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func New(objectCache objectcache.ObjectCache, config config.Config, mm ...metricsmanager.MetricsManager) libraries.Library {
	lib := &containerProfileLibrary{
		objectCache: objectCache,
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
		preStopCache:    GetPreStopHookCache(),
		detailedMetrics: config.ProfileProjection.DetailedMetricsEnabled,
	}
	if len(mm) > 0 {
		lib.metrics = mm[0]
	}
	return lib
}

func CP(objectCache objectcache.ObjectCache, config config.Config, mm ...metricsmanager.MetricsManager) cel.EnvOption {
	return cel.Lib(New(objectCache, config, mm...))
}

type containerProfileLibrary struct {
	objectCache     objectcache.ObjectCache
	functionCache   *cache.FunctionCache
	preStopCache    *PreStopHookCache
	metrics         metricsmanager.MetricsManager
	detailedMetrics bool
}

func (l *containerProfileLibrary) LibraryName() string {
	return "cp"
}

func (l *containerProfileLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *containerProfileLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"cp.was_executed": {
			cel.Overload(
				"cp_was_executed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_executed")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasExecuted(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_executed", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					// Convert "profile not available" error to false after cache layer
					// This ensures: 1) error is not cached, 2) rule evaluation continues normally
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_executed_with_args": {
			cel.Overload(
				"cp_was_executed_with_args", []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_executed_with_args")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasExecutedWithArgs(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_executed_with_args", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2])
					// Convert "profile not available" error to false after cache layer
					// This ensures: 1) error is not cached, 2) rule evaluation continues normally
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_path_opened": {
			cel.Overload(
				"cp_was_path_opened", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_path_opened")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpened(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_path_opened", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_path_opened_with_flags": {
			cel.Overload(
				"cp_was_path_opened_with_flags", []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_path_opened_with_flags")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithFlags(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_path_opened_with_flags", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_path_opened_with_suffix": {
			cel.Overload(
				"cp_was_path_opened_with_suffix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_path_opened_with_suffix")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithSuffix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_path_opened_with_suffix", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_path_opened_with_prefix": {
			cel.Overload(
				"cp_was_path_opened_with_prefix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_path_opened_with_prefix")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithPrefix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_path_opened_with_prefix", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_syscall_used": {
			cel.Overload(
				"cp_was_syscall_used", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_syscall_used")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasSyscallUsed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_syscall_used", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_capability_used": {
			cel.Overload(
				"cp_was_capability_used", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_capability_used")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasCapabilityUsed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_capability_used", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_endpoint_accessed": {
			cel.Overload(
				"cp_was_endpoint_accessed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_endpoint_accessed")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasEndpointAccessed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_endpoint_accessed", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_endpoint_accessed_with_method": {
			cel.Overload(
				"cp_was_endpoint_accessed_with_method", []*cel.Type{cel.StringType, cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_endpoint_accessed_with_method")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasEndpointAccessedWithMethod(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_endpoint_accessed_with_method", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_endpoint_accessed_with_methods": {
			cel.Overload(
				"cp_was_endpoint_accessed_with_methods", []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_endpoint_accessed_with_methods")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasEndpointAccessedWithMethods(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_endpoint_accessed_with_methods", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_endpoint_accessed_with_prefix": {
			cel.Overload(
				"cp_was_endpoint_accessed_with_prefix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_endpoint_accessed_with_prefix")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasEndpointAccessedWithPrefix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_endpoint_accessed_with_prefix", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_endpoint_accessed_with_suffix": {
			cel.Overload(
				"cp_was_endpoint_accessed_with_suffix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_endpoint_accessed_with_suffix")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasEndpointAccessedWithSuffix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_endpoint_accessed_with_suffix", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_host_accessed": {
			cel.Overload(
				"cp_was_host_accessed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_host_accessed")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasHostAccessed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_host_accessed", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
	}
}

func (l *containerProfileLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *containerProfileLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *containerProfileLibrary) CostEstimator() checker.CostEstimator {
	return &containerProfileCostEstimator{}
}

// containerProfileCostEstimator implements the checker.CostEstimator for the 'cp' library.
type containerProfileCostEstimator struct{}

func (e *containerProfileCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "cp.was_executed":
		// Cache lookup + O(n) linear search through execs list
		cost = 15
	case "cp.was_executed_with_args":
		// Cache lookup + O(n) linear search + O(m) slice comparison for args
		cost = 30
	case "cp.was_path_opened":
		// Cache lookup + O(n) linear search + dynamic path comparison
		cost = 25
	case "cp.was_path_opened_with_flags":
		// Cache lookup + O(n) search + dynamic path comparison + O(f*p) flag comparison
		cost = 40
	case "cp.was_path_opened_with_suffix":
		// Cache lookup + O(n) linear search + O(n*len(suffix)) string suffix checks
		cost = 20
	case "cp.was_path_opened_with_prefix":
		// Cache lookup + O(n) linear search + O(n*len(prefix)) string prefix checks
		cost = 20
	case "cp.was_syscall_used":
		// Cache lookup + O(n) slice.Contains search through syscalls
		cost = 12
	case "cp.was_capability_used":
		// Cache lookup + O(n) slice.Contains search through capabilities
		cost = 12
	case "cp.was_endpoint_accessed":
		// Cache lookup + O(n) linear search through endpoints + dynamic path comparison
		cost = 25
	case "cp.was_endpoint_accessed_with_method":
		// Cache lookup + O(n) search + dynamic path comparison + O(m) method check
		cost = 30
	case "cp.was_endpoint_accessed_with_methods":
		// Cache lookup + O(n) search + dynamic path comparison + O(m*k) method comparison
		cost = 35
	case "cp.was_endpoint_accessed_with_prefix":
		// Cache lookup + O(n) linear search + O(n*len(prefix)) string prefix checks
		cost = 20
	case "cp.was_endpoint_accessed_with_suffix":
		// Cache lookup + O(n) linear search + O(n*len(suffix)) string suffix checks
		cost = 20
	case "cp.was_host_accessed":
		// Cache lookup + O(n) endpoint search + URL parsing + O(m) network neighbor search
		cost = 35
	case "cp.was_internal_endpoint_accessed":
		// Cache lookup + O(n) linear search through endpoints checking internal flag
		cost = 15
	case "cp.was_external_endpoint_accessed":
		// Cache lookup + O(n) linear search through endpoints checking internal flag
		cost = 15
	case "cp.was_endpoint_accessed_with_direction":
		// Cache lookup + O(n) linear search through endpoints + string comparison
		cost = 18
	case "cp.was_endpoint_accessed_with_header":
		// Cache lookup + O(n) search + JSON unmarshal + header map lookup
		cost = 40
	case "cp.was_endpoint_accessed_with_header_value":
		// Cache lookup + O(n) search + JSON unmarshal + header map lookup + slice.Contains
		cost = 45
	default:
		// This estimator doesn't know about other functions.
		return nil
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *containerProfileCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*containerProfileCostEstimator)(nil)
var _ libraries.Library = (*containerProfileLibrary)(nil)
