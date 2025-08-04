package process

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func Process(config config.Config) cel.EnvOption {
	return cel.Lib(&processLibrary{
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	})
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

var _ libraries.Library = (*processLibrary)(nil)
