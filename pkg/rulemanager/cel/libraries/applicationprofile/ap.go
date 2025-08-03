package applicationprofile

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func AP(objectCache objectcache.ObjectCache, config config.Config) cel.EnvOption {
	return cel.Lib(&apLibrary{
		objectCache: objectCache,
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	})
}

type apLibrary struct {
	objectCache   objectcache.ObjectCache
	functionCache *cache.FunctionCache
}

func (l *apLibrary) LibraryName() string {
	return "ap"
}

func (l *apLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *apLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"ap.was_executed": {
			cel.Overload(
				"ap_was_executed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasExecuted(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_executed")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
		"ap.was_executed_with_args": {
			cel.Overload(
				"ap_was_executed_with_args", []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasExecutedWithArgs(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_executed_with_args")
					return cachedFunc(values[0], values[1], values[2])
				}),
			),
		},
		"ap.was_path_opened": {
			cel.Overload(
				"ap_was_path_opened", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpened(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_path_opened")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
		"ap.was_path_opened_with_flags": {
			cel.Overload(
				"ap_was_path_opened_with_flags", []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithFlags(args[0], args[1], args[2])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_path_opened_with_flags")
					return cachedFunc(values[0], values[1], values[2])
				}),
			),
		},
		"ap.was_path_opened_with_suffix": {
			cel.Overload(
				"ap_was_path_opened_with_suffix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithSuffix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_path_opened_with_suffix")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
		"ap.was_path_opened_with_prefix": {
			cel.Overload(
				"ap_was_path_opened_with_prefix", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasPathOpenedWithPrefix(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_path_opened_with_prefix")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
		"ap.was_syscall_used": {
			cel.Overload(
				"ap_was_syscall_used", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasSyscallUsed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_syscall_used")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
		"ap.was_capability_used": {
			cel.Overload(
				"ap_was_capability_used", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasCapabilityUsed(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "ap.was_capability_used")
					return cachedFunc(values[0], values[1])
				}),
			),
		},
	}
}

func (l *apLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *apLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

var _ libraries.Library = (*apLibrary)(nil)
