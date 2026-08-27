package containerprofile

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

func (l *containerProfileLibrary) wasPathOpened(containerID, path ref.Val) ref.Val {
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

// wasPathOpenedWithFlags answers whether the projected ApplicationProfile
// contains an open-entry whose path matches the given path. The flags
// argument is parsed and validated for shape but is not used for matching
// in v1 — the OpenFlagsByPath projection slice is out of scope for v1
// (composite-key projection would balloon the cache footprint). When the
// flags-projection slice is added in a future spec revision, this helper
// becomes the path-AND-flag matcher and v1 callers continue to work.
func (l *containerProfileLibrary) wasPathOpenedWithFlags(containerID, path, flags ref.Val) ref.Val {
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

func (l *containerProfileLibrary) wasPathOpenedWithSuffix(containerID, suffix ref.Val) ref.Val {
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
		// All entries retained (no rule declared SuffixHits-style projection).
		// Scan Values first, then Patterns.
		//
		// Patterns must be scanned. Volatile paths are ALWAYS stored as patterns,
		// so a correctly learned profile records the kubelet atomic-writer token
		// open as "/run/secrets/kubernetes.io/serviceaccount/⋯/token" — the
		// timestamped directory collapses, the "/token" leaf survives. Skipping
		// Patterns answers "no" for that profile and R0006 fires on every
		// SA-token read for the life of the workload; R0008 does the same via
		// "/proc/⋯/environ". See issue #98.
		//
		// strings.HasSuffix against pattern text is sound for the concrete
		// suffixes rules actually query: a pattern's trailing segments after the
		// last collapse token are literal, so if they end with the suffix then
		// every concrete path the pattern stands for ends with it too. A pattern
		// whose LEAF is itself a wildcard ("/var/log/pods/⋯") simply returns
		// false — the same answer as not scanning it, so this is never worse than
		// the previous behaviour.
		//
		// This also makes the two branches of this helper agree. When projection
		// is active, projection_apply.go builds SuffixHits with strings.HasSuffix
		// over every raw entry INCLUDING dynamic ones, so the projected branch
		// already answers true for "⋯/token". The Opens.All branch answering
		// false for the same profile was the inconsistency.
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
			l.metrics.IncProjectionUndeclaredLiteral("cp.was_path_opened_with_suffix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}

func (l *containerProfileLibrary) wasPathOpenedWithPrefix(containerID, prefix ref.Val) ref.Val {
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
		// All entries retained — scan Values, then Patterns. Symmetric with
		// wasPathOpenedWithSuffix above; see issue #98.
		//
		// A pattern's segments BEFORE the first collapse token are literal, so
		// strings.HasPrefix is sound for the concrete prefixes rules query: if the
		// pattern text starts with the prefix, every concrete path that pattern
		// stands for starts with it too. "/var/⋯/log" genuinely does have prefix
		// "/var/". A prefix that would reach past the first collapse token simply
		// fails to match — the same answer as not scanning, never worse.
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
			l.metrics.IncProjectionUndeclaredLiteral("cp.was_path_opened_with_prefix")
		}
		return types.Bool(false)
	}
	return types.Bool(hit)
}
