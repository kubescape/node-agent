package parse

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
	return &parseLibrary{
		functionCache: cache.NewFunctionCache(cache.FunctionCacheConfig{
			MaxSize: config.CelConfigCache.MaxSize,
			TTL:     config.CelConfigCache.TTL,
		}),
	}
}

func Parse(config config.Config) cel.EnvOption {
	return cel.Lib(New(config))
}

type parseLibrary struct {
	functionCache *cache.FunctionCache
}

func (l *parseLibrary) LibraryName() string {
	return "parse"
}

func (l *parseLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *parseLibrary) Declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"parse.get_exec_path": {
			cel.Overload(
				"parse_get_exec_path", []*cel.Type{cel.ListType(cel.StringType), cel.StringType}, cel.StringType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					return l.getExecPath(values[0], values[1])
				}),
			),
		},
	}
}

func (l *parseLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.Declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *parseLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (l *parseLibrary) CostEstimator() checker.CostEstimator {
	return &parseCostEstimator{}
}

// parseCostEstimator implements the checker.CostEstimator for the 'parse' library.
type parseCostEstimator struct{}

func (e *parseCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	cost := int64(0)
	switch function {
	case "parse.get_exec_path":
		// List parsing + simple array access + string comparison - O(1) operation
		cost = 5
	}
	return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: uint64(cost), Max: uint64(cost)}}
}

func (e *parseCostEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return nil // Not providing size estimates for now.
}

// Ensure the implementation satisfies the interface
var _ checker.CostEstimator = (*parseCostEstimator)(nil)
var _ libraries.Library = (*parseLibrary)(nil)
