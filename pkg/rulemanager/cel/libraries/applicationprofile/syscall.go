package applicationprofile

import (
	"slices"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
)

func (l *apLibrary) wasSyscallUsed(containerID, syscallName ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	syscallNameStr, ok := syscallName.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(syscallName)
	}

	container, _, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if slices.Contains(container.Syscalls, syscallNameStr) {
		return types.Bool(true)
	}

	return types.Bool(false)
}
