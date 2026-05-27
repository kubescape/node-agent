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

// wasPathOpenedWithFlags answers whether the projected ApplicationProfile
// contains an open-entry whose path matches the given path. The flags
// argument is parsed and validated for shape but is not used for matching
// in v1 — the OpenFlagsByPath projection slice is out of scope for v1
// (composite-key projection would balloon the cache footprint). When the
// flags-projection slice is added in a future spec revision, this helper
// becomes the path-AND-flag matcher and v1 callers continue to work.
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
		// All entries retained (no rule declared SuffixHits-style
		// projection). Scan concrete entries in Values first — exact
		// strings.HasSuffix is correct for those.
		for openPath := range cp.Opens.Values {
			if strings.HasSuffix(openPath, suffixStr) {
				return types.Bool(true)
			}
		}
		// Patterns hold dynamic entries (containing `*` / `⋯`). We
		// can't run strings.HasSuffix on the raw pattern text — a
		// pattern like "/var/log/pods/*/volumes/..." has wildcard
		// tokens that don't textually end with "foo.log" even though
		// its concrete realisations might. Matthias upstream PR #811
		// review: a NARROWER fallback is the answer here — split off
		// the pattern's concrete tail (the literal text after the
		// last wildcard segment) and only check HasSuffix against
		// that. If the pattern ends in a wildcard segment, the tail
		// is empty and concrete realisations could match ANY suffix —
		// be permissive (return true) to avoid the false-negative on
		// rules that omit profileDataRequired.opens.
		for _, openPattern := range cp.Opens.Patterns {
			tail := patternConcreteSuffix(openPattern)
			if tail == "" {
				return types.Bool(true)
			}
			if strings.HasSuffix(tail, suffixStr) {
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
		// All entries retained. Scan concrete entries in Values first —
		// exact strings.HasPrefix is correct for those.
		for openPath := range cp.Opens.Values {
			if strings.HasPrefix(openPath, prefixStr) {
				return types.Bool(true)
			}
		}
		// Patterns: same narrower-fallback strategy as the suffix path.
		// Split off the pattern's concrete head (the literal text
		// BEFORE the first wildcard segment). If the pattern starts
		// with a wildcard, concrete realisations could match ANY
		// prefix — be permissive. Matthias upstream PR #811 review.
		for _, openPattern := range cp.Opens.Patterns {
			head := patternConcretePrefix(openPattern)
			if head == "" {
				return types.Bool(true)
			}
			if strings.HasPrefix(head, prefixStr) {
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

// patternConcreteSuffix returns the literal text at the tail of a
// wildcard-bearing path pattern, dropped to start after the LAST
// wildcard segment's trailing `/`. Returns the input unchanged when
// no wildcard segments are present, or "" when the pattern ends in
// a wildcard segment (concrete realisations could match any suffix).
//
// Examples:
//
//	"/var/log/⋯/foo.log"  →  "foo.log"   (last wildcard `⋯`, concrete tail follows)
//	"/var/log/pods/*"     →  ""          (trailing wildcard, permissive caller)
//	"/var/log/foo.log"    →  "/var/log/foo.log"  (no wildcards, whole pattern)
//	"*"                   →  ""          (lone wildcard)
//
// Matthias upstream PR #811 review.
func patternConcreteSuffix(p string) string {
	lastWildEnd := -1
	i := 0
	for i < len(p) {
		segStart := i
		for i < len(p) && p[i] != '/' {
			i++
		}
		seg := p[segStart:i]
		if seg == "*" || seg == dynamicpathdetector.DynamicIdentifier {
			lastWildEnd = i
		}
		if i < len(p) {
			i++ // skip `/`
		}
	}
	if lastWildEnd < 0 {
		return p
	}
	if lastWildEnd >= len(p) {
		return ""
	}
	// lastWildEnd points at the `/` after the wildcard segment. Keep
	// the slash so callers querying with leading-slash suffixes match
	// correctly (every concrete realisation has that slash too).
	return p[lastWildEnd:]
}

// patternConcretePrefix is the mirror of patternConcreteSuffix —
// returns the literal text at the HEAD of the pattern up to (but not
// including) the first wildcard segment. Returns the input unchanged
// when no wildcard segments are present, or "" when the pattern starts
// with a wildcard segment.
//
// Matthias upstream PR #811 review.
func patternConcretePrefix(p string) string {
	i := 0
	for i < len(p) {
		segStart := i
		for i < len(p) && p[i] != '/' {
			i++
		}
		seg := p[segStart:i]
		if seg == "*" || seg == dynamicpathdetector.DynamicIdentifier {
			if segStart == 0 {
				return ""
			}
			// segStart is at the wildcard segment; the byte BEFORE it
			// is the `/` separator. Keep the slash in the returned
			// prefix so callers querying with trailing-slash prefixes
			// match (every concrete realisation has that slash too).
			return p[:segStart]
		}
		if i < len(p) {
			i++ // skip `/`
		}
	}
	return p
}

