package containerprofilenetwork

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
	lib := &containerProfileNetworkLibrary{
		objectCache: objectCache,
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
	if len(mm) > 0 && mm[0] != nil {
		lib.metrics = mm[0]
		lib.detailedMetrics = config.ProfileProjection.DetailedMetricsEnabled
	}
	return lib
}

func CPNetwork(objectCache objectcache.ObjectCache, config config.Config, mm ...metricsmanager.MetricsManager) cel.EnvOption {
	return cel.Lib(New(objectCache, config, mm...))
}

type containerProfileNetworkLibrary struct {
	objectCache     objectcache.ObjectCache
	functionCache   *cache.FunctionCache
	metrics         metricsmanager.MetricsManager
	detailedMetrics bool
}

func (l *containerProfileNetworkLibrary) LibraryName() string {
	return "cpnetwork"
}

func (l *containerProfileNetworkLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *containerProfileNetworkLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"cp.was_address_in_egress": {
			cel.Overload(
				"cp_was_address_in_egress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_address_in_egress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressInEgress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_address_in_egress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_address_in_ingress": {
			cel.Overload(
				"cp_was_address_in_ingress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_address_in_ingress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressInIngress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_address_in_ingress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		// Peer identity (namespace + labels) comes from IG's kubeipresolver
		// enrichment on the event, resolved cluster-wide. The functionCache is
		// intentionally bypassed here: a map argument does not produce a stable
		// scalar cache key, and the match is cheap (O(selectors)).
		"cp.was_selector_in_ingress": {
			cel.Overload(
				"cp_was_selector_in_ingress", []*cel.Type{cel.StringType, cel.StringType, cel.MapType(cel.StringType, cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_selector_in_ingress")
					}
					result := l.wasSelectorInIngress(values[0], values[1], values[2])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_selector_in_egress": {
			cel.Overload(
				"cp_was_selector_in_egress", []*cel.Type{cel.StringType, cel.StringType, cel.MapType(cel.StringType, cel.StringType)}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("expected 3 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_selector_in_egress")
					}
					result := l.wasSelectorInEgress(values[0], values[1], values[2])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.is_domain_in_egress": {
			cel.Overload(
				"cp_is_domain_in_egress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.is_domain_in_egress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.isDomainInEgress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.is_domain_in_egress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.is_domain_in_ingress": {
			cel.Overload(
				"cp_is_domain_in_ingress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.is_domain_in_ingress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.isDomainInIngress(args[0], args[1])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.is_domain_in_ingress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_address_port_protocol_in_egress": {
			cel.Overload(
				"cp_was_address_port_protocol_in_egress", []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 4 {
						return types.NewErr("expected 4 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_address_port_protocol_in_egress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressPortProtocolInEgress(args[0], args[1], args[2], args[3])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_address_port_protocol_in_egress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2], values[3])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
		"cp.was_address_port_protocol_in_ingress": {
			cel.Overload(
				"cp_was_address_port_protocol_in_ingress", []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 4 {
						return types.NewErr("expected 4 arguments, got %d", len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall("cp.was_address_port_protocol_in_ingress")
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return l.wasAddressPortProtocolInIngress(args[0], args[1], args[2], args[3])
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, "cp.was_address_port_protocol_in_ingress", cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values[0], values[1], values[2], values[3])
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		},
	}
}

func (l *containerProfileNetworkLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *containerProfileNetworkLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *containerProfileNetworkLibrary) CostEstimator() checker.CostEstimator {
	return &containerProfileNetworkCostEstimator{}
}

// containerProfileNetworkCostEstimator implements the checker.CostEstimator for the 'cpnetwork' library.
type containerProfileNetworkCostEstimator struct{}

func (e *containerProfileNetworkCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "cp.was_address_in_egress", "cp.was_address_in_ingress":
		// Cache lookup + O(n) linear search through egress/ingress list
		cost = 20
	case "cp.was_selector_in_ingress", "cp.was_selector_in_egress":
		// Profile projection lookup + O(selectors) label match against the
		// IG-enriched peer labels (no IP-to-pod resolution).
		cost = 30
	case "cp.is_domain_in_egress", "cp.is_domain_in_ingress":
		// Cache lookup + O(n) list iteration + O(m) slice.Contains on DNS names per entry
		cost = 35
	case "cp.was_address_port_protocol_in_egress", "cp.was_address_port_protocol_in_ingress":
		// Cache lookup + O(n) address search + O(p) nested port/protocol matching
		cost = 45
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *containerProfileNetworkCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*containerProfileNetworkCostEstimator)(nil)
var _ libraries.Library = (*containerProfileNetworkLibrary)(nil)
