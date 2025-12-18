package net

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
	return &netLibrary{
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
}

func Net(config config.Config) cel.EnvOption {
	return cel.Lib(New(config))
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

func (l *netLibrary) CostEstimator() checker.CostEstimator {
	return &netCostEstimator{}
}

// netCostEstimator implements the checker.CostEstimator for the 'net' library.
type netCostEstimator struct{}

func (e *netCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "net.is_private_ip":
		// IP parsing O(1) + byte comparison across 6 IP ranges O(6) = O(1)
		cost = 8
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *netCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*netCostEstimator)(nil)
var _ libraries.Library = (*netLibrary)(nil)
