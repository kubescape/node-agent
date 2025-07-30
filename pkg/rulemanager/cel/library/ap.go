package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
)

func AP(objectCache objectcache.ObjectCache) cel.EnvOption {
	return cel.Lib(&apLibrary{objectCache: objectCache})
}

type apLibrary struct {
	objectCache objectcache.ObjectCache
}

func (l *apLibrary) LibraryName() string {
	return "ap"
}

func (l *apLibrary) Types() []*cel.Type {
	return []*cel.Type{}
}

func (l *apLibrary) declarations() map[string][]cel.FunctionOpt {
	return map[string][]cel.FunctionOpt{
		"ap.was_executed": {
			cel.Overload(
				"ap_was_executed", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
					if len(values) != 2 {
						return types.NewErr("expected 2 arguments, got %d", len(values))
					}
					return l.wasExecuted(values[0], values[1])
				}),
			),
		},
	}
}

func (l *apLibrary) wasExecuted(containerID, path ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	pathStr, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}

	ap, err := profilehelper.GetApplicationProfile(containerIDStr, l.objectCache)
	if err != nil {
		return types.Bool(false)
	}

	containerName := profilehelper.GetContainerName(l.objectCache, containerIDStr)
	if containerName == "" {
		return types.Bool(false)
	}

	container, err := profilehelper.GetContainerFromApplicationProfile(ap, containerName)
	if err != nil {
		return types.Bool(false)
	}

	for _, exec := range container.Execs {
		if exec.Path == pathStr {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *apLibrary) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range l.declarations() {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (l *apLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

var _ Library = (*apLibrary)(nil)
