package state

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries"
)

func New(cfg config.Config) libraries.Library {
	return &stateLibrary{cfg: cfg}
}

// State registers the "state" variable and its read functions.
//
// Note what is NOT a parameter here: the store, the rule ID and the process tree.
// Reads are served by the per-(rule, event) Accessor injected into the eval
// context, so the library itself is immutable and safe to share across the
// worker pool. A library holding mutable per-evaluation state would race, since
// node-agent processes events concurrently against one shared cel.Env.
func State(cfg config.Config) cel.EnvOption {
	return cel.Lib(New(cfg))
}

type stateLibrary struct {
	cfg config.Config
}

func (l *stateLibrary) LibraryName() string {
	return "state"
}

func (l *stateLibrary) Types() []*cel.Type {
	return []*cel.Type{AccessorType}
}

// accessorOf recovers the receiver. A missing or wrong-typed receiver means the
// caller did not seed the eval context; report it as a miss-shaped value rather
// than an error so one misconfigured rule cannot abort evaluation.
func accessorOf(v ref.Val) (*Accessor, bool) {
	a, ok := v.Value().(*Accessor)
	return a, ok && a != nil
}

func stringOf(v ref.Val) (string, bool) {
	s, ok := v.Value().(string)
	return s, ok
}

func (l *stateLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"has": {
			cel.MemberOverload("state_has_name",
				[]*cel.Type{AccessorType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(target, name ref.Val) ref.Val {
					return hasImpl(target, name, types.String(""))
				}),
			),
			cel.MemberOverload("state_has_name_key",
				[]*cel.Type{AccessorType, cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.Bool(false)
					}
					return hasImpl(values[0], values[1], values[2])
				}),
			),
		},
		"get": {
			cel.MemberOverload("state_get_name",
				[]*cel.Type{AccessorType, cel.StringType}, cel.MapType(cel.StringType, cel.DynType),
				cel.BinaryBinding(func(target, name ref.Val) ref.Val {
					return getImpl(target, name, types.String(""))
				}),
			),
			cel.MemberOverload("state_get_name_key",
				[]*cel.Type{AccessorType, cel.StringType, cel.StringType}, cel.MapType(cel.StringType, cel.DynType),
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{})
					}
					return getImpl(values[0], values[1], values[2])
				}),
			),
		},
		"has_ancestor": {
			cel.MemberOverload("state_has_ancestor",
				[]*cel.Type{AccessorType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(target, name ref.Val) ref.Val {
					a, ok := accessorOf(target)
					if !ok {
						return types.Bool(false)
					}
					n, ok := stringOf(name)
					if !ok {
						return types.Bool(false)
					}
					_, hit := a.lookupAncestor(n)
					return types.Bool(hit)
				}),
			),
		},
		"get_ancestor": {
			cel.MemberOverload("state_get_ancestor",
				[]*cel.Type{AccessorType, cel.StringType}, cel.MapType(cel.StringType, cel.DynType),
				cel.BinaryBinding(func(target, name ref.Val) ref.Val {
					a, ok := accessorOf(target)
					if !ok {
						return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{})
					}
					n, ok := stringOf(name)
					if !ok {
						return a.emptyMap()
					}
					e, hit := a.lookupAncestor(n)
					if !hit {
						return a.emptyMap()
					}
					return a.entryVal(e)
				}),
			),
		},
	}
}

func hasImpl(target, name, key ref.Val) ref.Val {
	a, ok := accessorOf(target)
	if !ok {
		return types.Bool(false)
	}
	n, ok := stringOf(name)
	if !ok {
		return types.Bool(false)
	}
	k, ok := stringOf(key)
	if !ok {
		return types.Bool(false)
	}
	_, hit := a.lookup(n, k)
	return types.Bool(hit)
}

func getImpl(target, name, key ref.Val) ref.Val {
	a, ok := accessorOf(target)
	if !ok {
		return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{})
	}
	n, ok := stringOf(name)
	if !ok {
		return a.emptyMap()
	}
	k, ok := stringOf(key)
	if !ok {
		return a.emptyMap()
	}
	e, hit := a.lookup(n, k)
	if !hit {
		return a.emptyMap()
	}
	return a.entryVal(e)
}

func (l *stateLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{
		cel.Variable(AccessorContextKey, AccessorType),
	}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *stateLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *stateLibrary) CostEstimator() checker.CostEstimator {
	return &stateCostEstimator{cfg: l.cfg}
}

// stateCostEstimator implements checker.CostEstimator for the 'state' library.
type stateCostEstimator struct {
	cfg config.Config
}

// EstimateCallCost keys off overloadID, not the function name: this library's
// member functions are called "has" and "get", which are far too generic to
// match on -- another library declaring a "get" would silently receive these
// costs. Unknown overloads return nil so a composite estimator can fall through
// to the library that actually owns the function.
func (e *stateCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	var cost int64
	switch overloadID {
	case "state_has_name", "state_has_name_key", "state_get_name", "state_get_name_key":
		// One hash lookup under an RLock.
		cost = 10
	case "state_has_ancestor", "state_get_ancestor":
		// One probe per ancestor, so the depth bound is the multiplier.
		depth := e.cfg.CelStateStore.AncestorMaxDepth
		if depth <= 0 {
			depth = 8
		}
		cost = int64(10 * depth)
	default:
		return nil
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *stateCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

var _ checker.CostEstimator = (*stateCostEstimator)(nil)
var _ libraries.Library = (*stateLibrary)(nil)
