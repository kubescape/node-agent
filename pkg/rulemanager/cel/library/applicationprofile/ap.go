package applicationprofile

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

func AP(objectCache objectcache.ObjectCache) cel.EnvOption {
	return cel.Lib(&apLibrary{objectCache: objectCache})
}

type apLibrary struct {
	objectCache objectcache.ObjectCache
}

func (l *apLibrary) LibraryName() string {
	return "ap"
}

func (l *apLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *apLibrary) declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"ap.was_executed": {
			cel.Overload(
				"ap_was_executed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					return l.wasExecuted(values[0], values[1])
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
					return l.wasExecutedWithArgs(values[0], values[1], values[2])
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
					return l.wasPathOpened(values[0], values[1])
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
					return l.wasPathOpenedWithFlags(values[0], values[1], values[2])
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
					return l.wasSyscallUsed(values[0], values[1])
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
					return l.wasCapabilityUsed(values[0], values[1])
				}),
			),
		},
	}
}

func (l *apLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *apLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// var _ Library = (*apLibrary)(nil)
