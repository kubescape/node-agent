package networkneighborhood

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

func New(objectCache objectcache.ObjectCache, config config.Config) libraries.Library {
	return &nnLibrary{
		objectCache: objectCache,
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
}

func NN(objectCache objectcache.ObjectCache, config config.Config) cel.EnvOption {
	return cel.Lib(New(objectCache, config))
}

type nnLibrary struct {
	objectCache   objectcache.ObjectCache
	functionCache *cache.FunctionCache
}

func (l *nnLibrary) LibraryName() string {
	return "nn"
}

func (l *nnLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *nnLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"nn.was_address_in_egress": {
			cel.Overload(
				"nn_was_address_in_egress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressInEgress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.was_address_in_egress")
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"nn.was_address_in_ingress": {
			cel.Overload(
				"nn_was_address_in_ingress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressInIngress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.was_address_in_ingress")
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"nn.is_domain_in_egress": {
			cel.Overload(
				"nn_is_domain_in_egress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.isDomainInEgress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.is_domain_in_egress")
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"nn.is_domain_in_ingress": {
			cel.Overload(
				"nn_is_domain_in_ingress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.isDomainInIngress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.is_domain_in_ingress")
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"nn.was_address_port_protocol_in_egress": {
			cel.Overload(
				"nn_was_address_port_protocol_in_egress", []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 4 {
						return types.NewErr("expected 4 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressPortProtocolInEgress(args[0], args[1], args[2], args[3])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.was_address_port_protocol_in_egress")
					result := cachedFunc(values[0], values[1], values[2], values[3])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"nn.was_address_port_protocol_in_ingress": {
			cel.Overload(
				"nn_was_address_port_protocol_in_ingress", []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 4 {
						return types.NewErr("expected 4 arguments, got %d", len(values))
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressPortProtocolInIngress(args[0], args[1], args[2], args[3])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "nn.was_address_port_protocol_in_ingress")
					result := cachedFunc(values[0], values[1], values[2], values[3])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
	}
}

func (l *nnLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *nnLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *nnLibrary) CostEstimator() checker.CostEstimator {
	return &nnCostEstimator{}
}

// nnCostEstimator implements the checker.CostEstimator for the 'nn' library.
type nnCostEstimator struct{}

func (e *nnCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "nn.was_address_in_egress", "nn.was_address_in_ingress":
		// Cache lookup + O(n) linear search through egress/ingress list
		cost = 20
	case "nn.is_domain_in_egress", "nn.is_domain_in_ingress":
		// Cache lookup + O(n) list iteration + O(m) slice.Contains on DNS names per entry
		cost = 35
	case "nn.was_address_port_protocol_in_egress", "nn.was_address_port_protocol_in_ingress":
		// Cache lookup + O(n) address search + O(p) nested port/protocol matching
		cost = 45
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *nnCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*nnCostEstimator)(nil)
var _ libraries.Library = (*nnLibrary)(nil)
