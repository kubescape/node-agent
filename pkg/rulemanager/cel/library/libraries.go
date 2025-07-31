package library

import "github.com/google/cel-go/cel"

// Library represents a CEL library used by node-agent.
type Library interface {
	// SingletonLibrary provides the library name and ensures the library can be safely registered into environments.
	cel.SingletonLibrary

	// Types provides all custom types introduced by the library.
	Types() []*cel.Type

	// Declarations returns all function Declarations provided by the library.
	Declarations() map[string][]cel.FunctionOpt
}
