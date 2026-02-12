package parse

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
)

func (l *parseLibrary) getExecPath(args ref.Val, comm ref.Val) ref.Val {
	argsList, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	commStr, ok := comm.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(comm)
	}

	// Implement the logic from GetExecPathFromEvent
	if len(argsList) > 0 {
		if argsList[0] != "" {
			return types.String(argsList[0])
		}
	}
	return types.String(commStr)
}

func (l *parseLibrary) basename(path ref.Val) ref.Val {
	s, ok := path.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(path)
	}
	idx := strings.LastIndex(s, "/")
	if idx == -1 {
		return types.String(s)
	}
	return types.String(s[idx+1:])
}
