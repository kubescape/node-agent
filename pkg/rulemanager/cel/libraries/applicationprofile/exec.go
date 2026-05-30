package applicationprofile

import (
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

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

	// Check if preStop hook was triggered for this container
	if l.preStopCache != nil && l.preStopCache.WasPreStopTriggered(containerIDStr) {
		return types.Bool(true)
	}

	cp, _, err := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		// Return a special error that will NOT be cached, allowing retry when profile becomes available.
		// The caller should convert this to false after the cache layer.
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	if _, ok := cp.Execs.Values[pathStr]; ok {
		return types.Bool(true)
	}
	// Check Patterns (dynamic-segment entries).
	for _, execPath := range cp.Execs.Patterns {
		if dynamicpathdetector.CompareDynamic(execPath, pathStr) {
			return types.Bool(true)
		}
	}

	if l.isExecInPodSpec(containerID, path).Value().(bool) {
		return types.Bool(true)
	}

	return types.Bool(false)
}

func (l *apLibrary) wasExecutedWithArgs(containerID, path, args ref.Val) ref.Val {
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

	// Parse the runtime args list from CEL. Empty list is valid ("exec'd
	// with no args") and matches a profile entry whose Args is also empty
	// or absent (empty profile Args = "no argv constraint").
	runtimeArgs, err := celparse.ParseList[string](args)
	if err != nil {
	// Parse the runtime args list from CEL. Empty list is valid ("exec'd
	// with no args") and matches a profile entry whose Args is also empty
	// or absent (empty profile Args = "no argv constraint").
	runtimeArgs, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	// Check if preStop hook was triggered for this container
	if l.preStopCache != nil && l.preStopCache.WasPreStopTriggered(containerIDStr) {
		return types.Bool(true)
	}

	cp, _, perr := profilehelper.GetProjectedContainerProfile(l.objectCache, containerIDStr)
	if perr != nil {
		// Return a special error that will NOT be cached, allowing retry when profile becomes available.
		// The caller should convert this to false after the cache layer.
		return cache.NewProfileNotAvailableErr("%v", perr)
	}

	// Exact path match. ExecsByPath absent-vs-empty asymmetry: three states.
	//
	//  1. Path absent from cp.Execs.Values:
	//        Profile doesn't allow this exec at all → fall through to
	//        the pattern-match loop, then to false.
	//
	//  2. Path in Values, ABSENT from ExecsByPath (map lookup ok=false):
	//        Legacy / pre-args-projection profiles. Treated as
	//        "no argv constraint" — back-compat MATCH any args.
	//        This is the intentional fallback for profiles compiled
	//        against older storage versions that didn't populate the
	//        composite ExecsByPath surface.
	//
	//  3. Path in Values, PRESENT in ExecsByPath:
	//        Walk each profile argv vector with argvVectorMatches (handles
	//        DynamicIdentifier "⋯" and WildcardIdentifier "*"). Match if
	//        ANY vector matches. NOTE: per-vector matching uses
	//        argvVectorMatches, NOT dynamicpathdetector.CompareExecArgs
	//        directly — see the helper's doc for why an empty recorded
	//        vector must not act as a wildcard here.
	if _, ok := cp.Execs.Values[pathStr]; ok {
		if vectors, ok := cp.ExecsByPath[pathStr]; ok {
			for _, profileArgs := range vectors {
				if argvVectorMatches(profileArgs, runtimeArgs) {
					return types.Bool(true)
				}
			}
		} else {
			// State 2: ExecsByPath absent → back-compat "no argv constraint".
			return types.Bool(true)
		}
		if vectors, ok := cp.ExecsByPath[pathStr]; ok {
			for _, profileArgs := range vectors {
				if dynamicpathdetector.CompareExecArgs(profileArgs, runtimeArgs) {
					return types.Bool(true)
				}
			}
		} else {
			// State 2: ExecsByPath absent → back-compat "no argv constraint".
			return types.Bool(true)
		}
	}
	// Pattern path match: dynamic-segment paths in cp.Execs.Patterns.
	// Args matching mirrors the exact-path case — match against any
	// argv vector recorded for that pattern key.
	for _, execPath := range cp.Execs.Patterns {
		if dynamicpathdetector.CompareDynamic(execPath, pathStr) {
			if vectors, ok := cp.ExecsByPath[execPath]; ok {
				for _, profileArgs := range vectors {
					if argvVectorMatches(profileArgs, runtimeArgs) {
						return types.Bool(true)
					}
				}
			} else {
				return types.Bool(true)
			}
		}
	}

	if l.isExecInPodSpec(containerID, path).Value().(bool) {
		return types.Bool(true)
	}

	return types.Bool(false)
}

// argvVectorMatches reports whether ONE profile argv vector matches the
// runtime args. It is a PATH-AWARE superset of
// dynamicpathdetector.CompareExecArgs, composed from the primitives storage
// v0.0.278 already exports (CompareDynamic, WildcardIdentifier,
// DynamicIdentifier). Token semantics, anchored at both ends:
//
//   - "*"  (WildcardIdentifier)      — matches ZERO or more consecutive args.
//   - "⋯"  (bare DynamicIdentifier)  — matches EXACTLY ONE arg, any value.
//   - an arg that CONTAINS "⋯" but is not the bare token — a dynamic PATH;
//     compared against the runtime arg with dynamicpathdetector.CompareDynamic
//     (segment-wise, "⋯" = one path segment). This is the postgres /
//     versioned-binary case: profile argv[0]
//     "/usr/lib/postgresql/⋯/bin/postgres" must match the runtime
//     "/usr/lib/postgresql/16/bin/postgres". CompareExecArgs alone does only
//     literal "==" per position, so it never matched such args.
//   - anything else — literal string equality.
//
// Empty-vector semantics: an empty profile vector matches ONLY an empty
// runtime argv. A recorder/synthetic "ran with no args" entry must NOT act
// as a wildcard — otherwise it poisons the multi-vector OR in
// wasExecutedWithArgs and R0040 never fires (the #805 production failure).
// This falls out naturally from the anchored base case below, so no special
// guard is needed.
//
// Backtracking over "*" is memoised on (profileIndex, runtimeIndex) to stay
// quadratic, mirroring storage's matchExecArgsStrict.
func argvVectorMatches(profileArgs, runtimeArgs []string) bool {
	memo := make(map[[2]int]bool, (len(profileArgs)+1)*(len(runtimeArgs)+1))
	seen := make(map[[2]int]bool, (len(profileArgs)+1)*(len(runtimeArgs)+1))

	var match func(pi, ri int) bool
	match = func(pi, ri int) bool {
		key := [2]int{pi, ri}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true

		// Profile fully consumed → runtime must also be fully consumed
		// (anchored). With pi==0 this is the empty-vector case: empty
		// profile matches only empty runtime.
		if pi == len(profileArgs) {
			memo[key] = ri == len(runtimeArgs)
			return memo[key]
		}

		head := profileArgs[pi]

		if head == dynamicpathdetector.WildcardIdentifier {
			// Absorb 0..remaining runtime args into "*", first split wins.
			for k := ri; k <= len(runtimeArgs); k++ {
				if match(pi+1, k) {
					memo[key] = true
					return true
				}
			}
			memo[key] = false
			return false
		}

		// A non-wildcard head needs a runtime arg to consume.
		if ri == len(runtimeArgs) {
			memo[key] = false
			return false
		}

		if argTokenMatches(head, runtimeArgs[ri]) {
			memo[key] = match(pi+1, ri+1)
			return memo[key]
		}

		memo[key] = false
		return false
	}

	return match(0, 0)
}

// argTokenMatches compares ONE profile arg token against ONE runtime arg.
// Bare "⋯" matches any single arg; an arg embedding "⋯" is a dynamic path
// matched segment-wise via CompareDynamic; everything else is literal.
func argTokenMatches(profileArg, runtimeArg string) bool {
	if profileArg == dynamicpathdetector.DynamicIdentifier {
		return true // bare ⋯ — exactly one arg, any value
	}
	if strings.Contains(profileArg, dynamicpathdetector.DynamicIdentifier) {
		return dynamicpathdetector.CompareDynamic(profileArg, runtimeArg)
	}
	return profileArg == runtimeArg
}

func (l *apLibrary) isExecInPodSpec(containerID, path ref.Val) ref.Val {
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

	podSpec, err := profilehelper.GetPodSpec(l.objectCache, containerIDStr)
	if err != nil {
		logger.L().Error("isExecInPodSpec - failed to get pod spec", helpers.String("error", err.Error()))
		return types.Bool(false)
	}

	containerName := profilehelper.GetContainerName(l.objectCache, containerIDStr)
	if containerName == "" {
		logger.L().Error("isExecInPodSpec - failed to get container name", helpers.String("containerID", containerIDStr))
		return types.Bool(false)
	}

	if podSpec.Containers != nil {
		for _, container := range podSpec.Containers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	if podSpec.InitContainers != nil {
		for _, container := range podSpec.InitContainers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	if podSpec.EphemeralContainers != nil {
		for _, container := range podSpec.EphemeralContainers {
			if container.Name == containerName {
				if container.Command != nil {
					for _, exec := range container.Command {
						if exec == pathStr {
							return types.Bool(true)
						}
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PreStop.Exec.Command {
							if exec == pathStr {
								if l.preStopCache != nil {
									l.preStopCache.MarkPreStopTriggered(containerIDStr)
								}
								return types.Bool(true)
							}
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						for _, exec := range container.Lifecycle.PostStart.Exec.Command {
							if exec == pathStr {
								return types.Bool(true)
							}
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	return types.Bool(false)
}
