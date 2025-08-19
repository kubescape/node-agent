package process

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func New(config config.Config) libraries.Library {
	return &processLibrary{
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
}

func Process(config config.Config) cel.EnvOption {
	return cel.Lib(New(config))
}

type processLibrary struct {
	functionCache *cache.FunctionCache
}

func (l *processLibrary) LibraryName() string {
	return "process"
}

func (l *processLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *processLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"process.get_process_env": {
			cel.Overload(
				"process_get_process_env", []*cel.Type{cel.IntType}, cel.MapType(cel.StringType, cel.StringType),
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 1 {
						return types.NewErr("expected 1 argument, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.getProcessEnv(args[0])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "process.get_process_env")
					return cachedFunc(values[0])
				}),
			),
		},
		"process.get_ld_hook_var": {
			cel.Overload(
				"process_get_ld_hook_var", []*cel.Type{cel.UintType}, cel.StringType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 1 {
						return types.NewErr("expected 1 argument, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.getLdHookVar(args[0])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "process.get_ld_hook_var")
					return cachedFunc(values[0])
				}),
			),
		},
	}
}

func (l *processLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *processLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *processLibrary) CostEstimator() checker.CostEstimator {
	return &processCostEstimator{}
}

// processCostEstimator implements the checker.CostEstimator for the 'process' library.
type processCostEstimator struct{}

func (e *processCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "process.get_process_env":
		// File I/O to read /proc/{pid}/environ + O(n) parsing of environment variables
		cost = 50
	case "process.get_ld_hook_var":
		// File I/O + O(n) environment parsing + O(m) LD_PRELOAD array search (m=41 constants)
		cost = 60
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *processCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*processCostEstimator)(nil)
var _ libraries.Library = (*processLibrary)(nil)
