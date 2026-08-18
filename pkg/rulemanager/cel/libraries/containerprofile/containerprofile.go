package containerprofile

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

// AP returns the deprecated "ap.*" backward-compat alias namespace for this
// library's cp.* functions (e.g. ap.was_executed, ap.was_path_opened, ...).
//
// Deprecated: kubescape/node-agent#864 renamed the ap.*/nn.* CEL helper
// namespaces to cp.* with no backward-compatible aliases, which silently
// disabled any pre-existing user-authored CEL rule still referencing the old
// names (pkg/utils/cel.go logs a warning and just skips the rule on compile
// failure). AP restores those names for a transition window: it shares the
// same containerProfileLibrary instance and the same funcSpecs table as
// cp.*, so every ap.* call is wired to the exact same Go implementation
// (l.wasExecuted, l.wasPathOpened, ...) as its cp.* equivalent — only the
// CEL-facing function name and overload id differ (cel-go requires overload
// ids to be unique per environment, so ap.* can't literally reuse cp.*'s
// FunctionOpt values). Remove once user rules have migrated to cp.*.
func AP(objectCache objectcache.ObjectCache, config config.Config, mm ...metricsmanager.MetricsManager) cel.EnvOption {
	base := New(objectCache, config, mm...).(*containerProfileLibrary)
	return cel.Lib(&legacyContainerProfileLibrary{base: base, name: "ap", prefix: "ap."})
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

// containerProfileFuncSpec describes one CEL helper's overload signature and
// its (single, shared) Go implementation. Declarations() below and the ap.*
// legacy alias both build their cel.FunctionOpt map from this same table, so
// the two namespaces can never register a different implementation for the
// "same" function name.
type containerProfileFuncSpec struct {
	// name is the function's suffix, e.g. "was_executed" (used after the
	// "cp."/"ap." namespace prefix, and after the "cp_"/"ap_" overload-id
	// prefix).
	name       string
	argTypes   []*cel.Type
	resultType *cel.Type
	arity      int
	// call invokes the shared implementation method on l.
	call func(l *containerProfileLibrary, args []ref.Val) ref.Val
}

var containerProfileFuncSpecs = []containerProfileFuncSpec{
	{
		name:       "was_executed",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasExecuted(a[0], a[1]) },
	},
	{
		name:       "was_executed_with_args",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)},
		resultType: cel.BoolType,
		arity:      3,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasExecutedWithArgs(a[0], a[1], a[2]) },
	},
	{
		name:       "was_path_opened",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasPathOpened(a[0], a[1]) },
	},
	{
		name:       "was_path_opened_with_flags",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)},
		resultType: cel.BoolType,
		arity:      3,
		call: func(l *containerProfileLibrary, a []ref.Val) ref.Val {
			return l.wasPathOpenedWithFlags(a[0], a[1], a[2])
		},
	},
	{
		name:       "was_path_opened_with_suffix",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasPathOpenedWithSuffix(a[0], a[1]) },
	},
	{
		name:       "was_path_opened_with_prefix",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasPathOpenedWithPrefix(a[0], a[1]) },
	},
	{
		name:       "was_syscall_used",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasSyscallUsed(a[0], a[1]) },
	},
	{
		name:       "was_capability_used",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasCapabilityUsed(a[0], a[1]) },
	},
	{
		name:       "was_endpoint_accessed",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasEndpointAccessed(a[0], a[1]) },
	},
	{
		name:       "was_endpoint_accessed_with_method",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      3,
		call: func(l *containerProfileLibrary, a []ref.Val) ref.Val {
			return l.wasEndpointAccessedWithMethod(a[0], a[1], a[2])
		},
	},
	{
		name:       "was_endpoint_accessed_with_methods",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType, cel.ListType(cel.StringType)},
		resultType: cel.BoolType,
		arity:      3,
		call: func(l *containerProfileLibrary, a []ref.Val) ref.Val {
			return l.wasEndpointAccessedWithMethods(a[0], a[1], a[2])
		},
	},
	{
		name:       "was_endpoint_accessed_with_prefix",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileLibrary, a []ref.Val) ref.Val {
			return l.wasEndpointAccessedWithPrefix(a[0], a[1])
		},
	},
	{
		name:       "was_endpoint_accessed_with_suffix",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call: func(l *containerProfileLibrary, a []ref.Val) ref.Val {
			return l.wasEndpointAccessedWithSuffix(a[0], a[1])
		},
	},
	{
		name:       "was_host_accessed",
		argTypes:   []*cel.Type{cel.StringType, cel.StringType},
		resultType: cel.BoolType,
		arity:      2,
		call:       func(l *containerProfileLibrary, a []ref.Val) ref.Val { return l.wasHostAccessed(a[0], a[1]) },
	},
}

// declarationsWithPrefix builds the cel.FunctionOpt map for every function in
// containerProfileFuncSpecs, exposed as "<namePrefix><spec.name>" (e.g.
// "cp.was_executed" or "ap.was_executed") with overload id
// "<overloadIDPrefix>_<spec.name>" (e.g. "cp_was_executed" / "ap_was_executed" —
// cel-go requires overload ids to be unique per environment, so the ap.*
// alias needs its own ids even though it shares spec.call's implementation).
func (l *containerProfileLibrary) declarationsWithPrefix(namePrefix, overloadIDPrefix string) map[string][]cel.FunctionOpt {
	decls := make(map[string][]cel.FunctionOpt, len(containerProfileFuncSpecs))
	for _, spec := range containerProfileFuncSpecs {
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
					wrapperFunc := func(args ...ref.Val) ref.Val {
						return spec.call(l, args)
					}
					cachedFunc := l.functionCache.WithCache(wrapperFunc, fullName, cache.HashForContainerProfile(l.objectCache))
					result := cachedFunc(values...)
					// Convert "profile not available" error to false after cache layer
					// This ensures: 1) error is not cached, 2) rule evaluation continues normally
					return cache.ConvertProfileNotAvailableErrToBool(result, false)
				}),
			),
		}
	}
	return decls
}

func (l *containerProfileLibrary) Declarations() map[string][]cel.FunctionOpt {
	return l.declarationsWithPrefix("cp.", "cp")
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

// legacyContainerProfileLibrary re-exposes a containerProfileLibrary's
// funcSpecs under a legacy namespace prefix (e.g. "ap."). See AP() above.
type legacyContainerProfileLibrary struct {
	base   *containerProfileLibrary
	name   string // LibraryName(), e.g. "ap"
	prefix string // function-name prefix, e.g. "ap."
}

func (l *legacyContainerProfileLibrary) LibraryName() string {
	return l.name
}

func (l *legacyContainerProfileLibrary) Types() []*cel.Type {
	return l.base.Types()
}

func (l *legacyContainerProfileLibrary) Declarations() map[string][]cel.FunctionOpt {
	return l.base.declarationsWithPrefix(l.prefix, strings.TrimSuffix(l.prefix, "."))
}

func (l *legacyContainerProfileLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *legacyContainerProfileLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// CostEstimator translates the legacy function name back to its canonical
// "cp." form and delegates to the base library's estimator, so ap.* calls
// get the same cost estimate as their cp.* equivalent.
func (l *legacyContainerProfileLibrary) CostEstimator() checker.CostEstimator {
	return &legacyCostEstimator{inner: l.base.CostEstimator(), legacyPrefix: l.prefix, canonicalPrefix: "cp."}
}

// legacyCostEstimator adapts a checker.CostEstimator built for the "cp."
// namespace so it also answers for a legacy-prefixed function name by
// translating the prefix before delegating.
type legacyCostEstimator struct {
	inner           checker.CostEstimator
	legacyPrefix    string
	canonicalPrefix string
}

func (e *legacyCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	if strings.HasPrefix(function, e.legacyPrefix) {
		function = e.canonicalPrefix + strings.TrimPrefix(function, e.legacyPrefix)
	}
	return e.inner.EstimateCallCost(function, overloadID, target, args)
}

func (e *legacyCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return e.inner.EstimateSize(element)
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
	// Endpoint/HTTP predicates below are not declared or implemented in this build (dead in OSS); cost entries retained for parity with builds that register them.
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
var _ checker.CostEstimator = (*legacyCostEstimator)(nil)
var _ libraries.Library = (*containerProfileLibrary)(nil)
var _ libraries.Library = (*legacyContainerProfileLibrary)(nil)
