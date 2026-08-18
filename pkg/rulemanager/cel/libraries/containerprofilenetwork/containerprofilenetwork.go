package containerprofilenetwork

import (
	"strings"

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

// NN returns the deprecated "nn.*" backward-compat alias namespace for this
// library's cp.* functions (e.g. nn.is_domain_in_egress,
// nn.was_address_in_egress, ...).
//
// Deprecated: kubescape/node-agent#864 renamed the ap.*/nn.* CEL helper
// namespaces to cp.* with no backward-compatible aliases, which silently
// disabled any pre-existing user-authored CEL rule still referencing the old
// names (pkg/utils/cel.go logs a warning and just skips the rule on compile
// failure). NN restores those names for a transition window: it shares the
// same containerProfileNetworkLibrary instance and the same funcSpecs table
// as cp.*, so every nn.* call is wired to the exact same Go implementation
// (l.wasAddressInEgress, l.isDomainInEgress, ...) as its cp.* equivalent —
// only the CEL-facing function name and overload id differ (cel-go requires
// overload ids to be unique per environment, so nn.* can't literally reuse
// cp.*'s FunctionOpt values). Remove once user rules have migrated to cp.*.
func NN(objectCache objectcache.ObjectCache, config config.Config, mm ...metricsmanager.MetricsManager) cel.EnvOption {
	base := New(objectCache, config, mm...).(*containerProfileNetworkLibrary)
	return cel.Lib(&legacyContainerProfileNetworkLibrary{base: base, name: "nn", prefix: "nn."})
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

// containerProfileNetworkFuncSpec describes one CEL helper's overload
// signature and its (single, shared) Go implementation. Declarations()
// below and the nn.* legacy alias both build their cel.FunctionOpt map from
// this same table, so the two namespaces can never register a different
// implementation for the "same" function name.
type containerProfileNetworkFuncSpec struct {
	// name is the function's suffix, e.g. "was_address_in_egress" (used
	// after the "cp."/"nn." namespace prefix, and after the "cp_"/"nn_"
	// overload-id prefix).
	name       string
	argTypes   []*cel.Type
	resultType *cel.Type
	arity      int
	// call invokes the shared implementation method on l.
	call func(l *containerProfileNetworkLibrary, args []ref.Val) ref.Val
	// noCache bypasses the functionCache: a map argument has no stable scalar
	// cache key, and the selector match is cheap (O(selectors)).
	noCache bool
}

var containerProfileNetworkFuncSpecs = []containerProfileNetworkFuncSpec{
	{
		name:       "was_address_in_egress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasAddressInEgress(a[0], a[1])
		},
	},
	{
		name:       "was_address_in_ingress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasAddressInIngress(a[0], a[1])
		},
	},
	{
		name:       "is_domain_in_egress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.isDomainInEgress(a[0], a[1])
		},
	},
	{
		name:       "is_domain_in_ingress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.isDomainInIngress(a[0], a[1])
		},
	},
	{
		name:       "was_address_port_protocol_in_egress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType},
		resultType: cel.BoolType,
		arity:      4,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasAddressPortProtocolInEgress(a[0], a[1], a[2], a[3])
		},
	},
	{
		name:       "was_address_port_protocol_in_ingress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.IntType, cel.StringType},
		resultType: cel.BoolType,
		arity:      4,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasAddressPortProtocolInIngress(a[0], a[1], a[2], a[3])
		},
	},
	{
		name:       "was_selector_in_egress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.MapType(cel.StringType, cel.StringType)},
		resultType: cel.BoolType,
		arity:      3,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasSelectorInEgress(a[0], a[1], a[2])
		},
		noCache: true,
	},
	{
		name:       "was_selector_in_ingress",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.MapType(cel.StringType, cel.StringType)},
		resultType: cel.BoolType,
		arity:      3,
		call: func(l *containerProfileNetworkLibrary, a []ref.Val) ref.Val {
			return l.wasSelectorInIngress(a[0], a[1], a[2])
		},
		noCache: true,
	},
}

// declarationsWithPrefix builds the cel.FunctionOpt map for every function in
// containerProfileNetworkFuncSpecs, exposed as "<namePrefix><spec.name>"
// (e.g. "cp.was_address_in_egress" or "nn.was_address_in_egress") with
// overload id "<overloadIDPrefix>_<spec.name>" (e.g.
// "cp_was_address_in_egress" / "nn_was_address_in_egress" — cel-go requires
// overload ids to be unique per environment, so the nn.* alias needs its own
// ids even though it shares spec.call's implementation).
func (l *containerProfileNetworkLibrary) declarationsWithPrefix(namePrefix, overloadIDPrefix string) map[string][]cel.FunctionOpt {
	decls := make(map[string][]cel.FunctionOpt, len(containerProfileNetworkFuncSpecs))
	for _, spec := range containerProfileNetworkFuncSpecs {
		spec := spec
		fullName := namePrefix + spec.name
		overloadID := overloadIDPrefix + "_" + spec.name
		decls[fullName] = []cel.FunctionOpt{
			cel.Overload(
				overloadID, spec.argTypes, spec.resultType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != spec.arity {
						return types.NewErr("expected %d arguments, got %d", spec.arity, len(values))
					}
					if l.detailedMetrics && l.metrics != nil {
						l.metrics.IncHelperCall(fullName)
					}
					if spec.noCache {
						return cache.ConvertProfileNotAvailableErrToBool(spec.call(l, values), false)
					}
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return spec.call(l, args)
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, fullName, cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values...)
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		}
	}
	return decls
}

func (l *containerProfileNetworkLibrary) Declarations() map[string][]cel.FunctionOpt {
	return l.declarationsWithPrefix("cp.", "cp")
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

// legacyContainerProfileNetworkLibrary re-exposes a
// containerProfileNetworkLibrary's funcSpecs under a legacy namespace prefix
// (e.g. "nn."). See NN() above.
type legacyContainerProfileNetworkLibrary struct {
	base   *containerProfileNetworkLibrary
	name   string // LibraryName(), e.g. "nn"
	prefix string // function-name prefix, e.g. "nn."
}

func (l *legacyContainerProfileNetworkLibrary) LibraryName() string {
	return l.name
}

func (l *legacyContainerProfileNetworkLibrary) Types() []*cel.Type {
	return l.base.Types()
}

func (l *legacyContainerProfileNetworkLibrary) Declarations() map[string][]cel.FunctionOpt {
	return l.base.declarationsWithPrefix(l.prefix, strings.TrimSuffix(l.prefix, "."))
}

func (l *legacyContainerProfileNetworkLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *legacyContainerProfileNetworkLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// CostEstimator translates the legacy function name back to its canonical
// "cp." form and delegates to the base library's estimator, so nn.* calls
// get the same cost estimate as their cp.* equivalent.
func (l *legacyContainerProfileNetworkLibrary) CostEstimator() checker.CostEstimator {
	return &legacyNetworkCostEstimator{inner: l.base.CostEstimator(), legacyPrefix: l.prefix, canonicalPrefix: "cp."}
}

// legacyNetworkCostEstimator adapts a checker.CostEstimator built for the
// "cp." namespace so it also answers for a legacy-prefixed function name by
// translating the prefix before delegating.
type legacyNetworkCostEstimator struct {
	inner           checker.CostEstimator
	legacyPrefix    string
	canonicalPrefix string
}

func (e *legacyNetworkCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	if strings.HasPrefix(function, e.legacyPrefix) {
		function = e.canonicalPrefix + strings.TrimPrefix(function, e.legacyPrefix)
	}
	return e.inner.EstimateCallCost(function, overloadID, target, args)
}

func (e *legacyNetworkCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return e.inner.EstimateSize(element)
}

// containerProfileNetworkCostEstimator implements the checker.CostEstimator for the 'cpnetwork' library.
type containerProfileNetworkCostEstimator struct{}

func (e *containerProfileNetworkCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "cp.was_address_in_egress", "cp.was_address_in_ingress":
		// Cache lookup + O(n) linear search through egress/ingress list
		cost = 20
	case "cp.is_domain_in_egress", "cp.is_domain_in_ingress":
		// Cache lookup + O(n) list iteration + O(m) slice.Contains on DNS names per entry
		cost = 35
	case "cp.was_selector_in_egress", "cp.was_selector_in_ingress":
		// O(selectors) label-set match per peer entry
		cost = 30
	case "cp.was_address_port_protocol_in_egress", "cp.was_address_port_protocol_in_ingress":
		// Cache lookup + O(n) address search + O(p) nested port/protocol matching
		cost = 45
	default:
		return nil
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *containerProfileNetworkCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*containerProfileNetworkCostEstimator)(nil)
var _ checker.CostEstimator = (*legacyNetworkCostEstimator)(nil)
var _ libraries.Library = (*containerProfileNetworkLibrary)(nil)
var _ libraries.Library = (*legacyContainerProfileNetworkLibrary)(nil)
