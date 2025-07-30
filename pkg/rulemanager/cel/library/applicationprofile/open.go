package applicationprofile

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

func (l *apLibrary) wasPathOpened(containerID, path ref.Val) ref.Val {
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

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, open := range container.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, pathStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *apLibrary) wasPathOpenedWithFlags(containerID, path, flags ref.Val) ref.Val {
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

	celFlags, err := ParseList[string](flags)
	if err != nil {
		return types.NewErr("failed to parse flags: %v", err)
	}

	container, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, open := range container.Opens {
		if dynamicpathdetector.CompareDynamic(open.Path, pathStr) {
			if compareOpenFlags(celFlags, open.Flags) {
				return types.Bool(true)
			}
		}
	}

	return types.Bool(false)
}

func compareOpenFlags(eventOpenFlags []string, profileOpenFlags []string) bool {
	found := 0
	for _, eventOpenFlag := range eventOpenFlags {
		for _, profileOpenFlag := range profileOpenFlags {
			if eventOpenFlag == profileOpenFlag {
				found += 1
			}
		}
	}
	return found == len(eventOpenFlags)
}
