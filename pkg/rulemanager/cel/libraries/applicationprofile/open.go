package applicationprofile

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
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

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	// All=true means all observed entries were retained in Values — still need to query Values.
	for openPath := range cp.Opens.Values {
		if dynamicpathdetector.CompareDynamic(openPath, pathStr) {
			return types.Bool(true)
		}
	}
	// Check Patterns (dynamic-segment entries).
	for _, openPath := range cp.Opens.Patterns {
		if dynamicpathdetector.CompareDynamic(openPath, pathStr) {
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

	// flags projection (OpenFlagsByPath) is out of scope for v1; degrade to path-only matching.
	if _, err := celparse.ParseList[string](flags); err != nil {
		return types.NewErr("failed to parse flags: %v", err)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for openPath := range cp.Opens.Values {
		if dynamicpathdetector.CompareDynamic(openPath, pathStr) {
			return types.Bool(true)
		}
	}
	for _, openPath := range cp.Opens.Patterns {
		if dynamicpathdetector.CompareDynamic(openPath, pathStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *apLibrary) wasPathOpenedWithSuffix(containerID, suffix ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	suffixStr, ok := suffix.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(suffix)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if cp.Opens.All {
		// All entries retained — scan to check for the suffix.
		for openPath := range cp.Opens.Values {
			if strings.HasSuffix(openPath, suffixStr) {
				return types.Bool(true)
			}
		}
		for _, openPath := range cp.Opens.Patterns {
			if strings.HasSuffix(openPath, suffixStr) {
				return types.Bool(true)
			}
		}
		return types.Bool(false)
	}
	// Projection applied — SuffixHits is authoritative; absent key = undeclared.
	hit, declared := cp.Opens.SuffixHits[suffixStr]
	if !declared {
		if l.metrics != nil {
			l.metrics.IncProjectionUndeclaredLiteral("ap.was_path_opened_with_suffix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}

func (l *apLibrary) wasPathOpenedWithPrefix(containerID, prefix ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	prefixStr, ok := prefix.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(prefix)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if cp.Opens.All {
		// All entries retained — scan to check for the prefix.
		for openPath := range cp.Opens.Values {
			if strings.HasPrefix(openPath, prefixStr) {
				return types.Bool(true)
			}
		}
		for _, openPath := range cp.Opens.Patterns {
			if strings.HasPrefix(openPath, prefixStr) {
				return types.Bool(true)
			}
		}
		return types.Bool(false)
	}
	// Projection applied — PrefixHits is authoritative; absent key = undeclared.
	hit, declared := cp.Opens.PrefixHits[prefixStr]
	if !declared {
		if l.metrics != nil {
			l.metrics.IncProjectionUndeclaredLiteral("ap.was_path_opened_with_prefix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}

