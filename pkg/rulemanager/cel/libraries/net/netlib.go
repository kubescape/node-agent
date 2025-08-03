package net

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
)

func Net(config config.Config) cel.EnvOption {
	return cel.Lib(&netLibrary{
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	})
}

type netLibrary struct {
	functionCache *cache.FunctionCache
}

func (l *netLibrary) LibraryName() string {
	return "net"
}

func (l *netLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *netLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"net.is_private_ip": {
			cel.Overload(
				"net_is_private_ip", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 1 {
						return types.NewErr("expected 1 argument, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.isPrivateIP(args[0])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "net.is_private_ip")
					return cachedFunc(values[0])
				}),
			),
		},
	}
}

func (l *netLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *netLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

var _ libraries.Library = (*netLibrary)(nil)
