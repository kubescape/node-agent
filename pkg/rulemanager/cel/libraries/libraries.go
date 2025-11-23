package libraries

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
)

// Library represents a CEL library used by node-agent.
type Library interface {
	// SingletonLibrary provides the library name and ensures the library can be safely registered into environments.
	cel.SingletonLibrary

	// Types provides all custom types introduced by the library.
	Types() []*cel.Type

	// Declarations returns all function Declarations provided by the library.
	Declarations() map[string][]cel.FunctionOpt

	// CostEstimator provides a cost estimator for the library.
	CostEstimator() checker.CostEstimator
}
