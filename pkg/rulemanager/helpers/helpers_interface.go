package helpers

import "github.com/google/cel-go/cel"

type CELHelperFunctionProvider interface {
	CreateCELHelperFunctions() []cel.EnvOption
}
