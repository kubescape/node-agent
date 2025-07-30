package networkneighborhood

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
)

func NN(objectCache objectcache.ObjectCache) cel.EnvOption {
	return cel.Lib(&nnLibrary{objectCache: objectCache})
}

type nnLibrary struct {
	objectCache objectcache.ObjectCache
}

func (l *nnLibrary) LibraryName() string {
	return "nn"
}

func (l *nnLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *nnLibrary) declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"nn.was_address_in_egress": {
			cel.Overload(
				"nn_was_address_in_egress", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					return l.wasAddressInEgress(values[0], values[1])
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
					return l.wasAddressInIngress(values[0], values[1])
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
					return l.isDomainInEgress(values[0], values[1])
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
					return l.isDomainInIngress(values[0], values[1])
				}),
			),
		},
	}
}

func (l *nnLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *nnLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
