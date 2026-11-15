package containerprofile

import (
	"path"
	"slices"
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

func (l *containerProfileLibrary) wasExecuted(containerID, path ref.Val) ref.Val {
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

	if pathStr == "" {
		return types.Bool(false)
	}

	if matchLiteralPath(cp.Execs.Values, pathStr) {
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

func (l *containerProfileLibrary) wasExecutedWithArgs(containerID, path, args ref.Val) ref.Val {
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

	// Parse the runtime args list from CEL. An empty list is valid: it means
	// argv was not captured, and matchExecArgv treats it as unknown (match).
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

	// Exact path match: match the runtime argv against every argv vector
	// recorded for that path with matchExecArgv (B1′, see its doc comment).
	//
	// Three profile states:
	//
	//   1. Path absent from cp.Execs.Values: the profile does not allow this
	//      exec → fall through to the pattern loop, then to false.
	//
	//   2. Path in Values, absent from ExecsByPath: a legacy or
	//      pre-args-projection profile → no argv constraint, match.
	//
	//   3. Path in Values with recorded vectors: each vector is matched by
	//      matchExecArgv. An EMPTY vector ([]) means "no argv constraint" and
	//      matches any runtime argv (storage CompareExecArgs,
	//      compare_exec_args.go). It is not "must have no args": the stored
	//      Args is omitempty, so [] and nil cannot be told apart.
	//
	// Exec-arg wildcards are "⋯" (exactly one arg, or one path segment inside
	// an arg) and "⋯⋯" (zero or more whole args). "*" is never a wildcard: it
	// is matched literally, because a process is routinely invoked with an
	// unexpanded shell glob.
	if _, ok := cp.Execs.Values[pathStr]; ok {
		if vectors, ok := cp.ExecsByPath[pathStr]; ok {
			for _, profileArgs := range vectors {
				if matchExecArgv(profileArgs, runtimeArgs) {
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
					if matchExecArgv(profileArgs, runtimeArgs) {
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

// matchExecArgv reports whether a runtime argv (argv[0] included) satisfies
// a recorded profile argv vector (B1′).
//
//   - An empty profile vector is "no constraint" and matches anything.
//   - An empty or nil runtime argv is an unknown capture (the tracer could not
//     read argv), not "ran with no arguments", so it matches and R0040 does not
//     fire. R0001 still covers the path.
//   - If profile[0] contains "⋯", the full vectors are compared with the
//     storage matcher.
//   - Otherwise argv[0] is compared by basename, ignoring one leading "-"
//     (login shells), so a profile learned with "/bin/sh" matches the real
//     argv[0] "sh" while busybox applets ("ls" vs "cat") stay distinct. The
//     rest of the vectors is compared with the storage matcher. A one-element
//     profile requires a one-element runtime argv, because the storage matcher
//     would treat the empty remainder as "no constraint".
func matchExecArgv(profileArgs, runtimeArgs []string) bool {
	if len(profileArgs) == 0 || len(runtimeArgs) == 0 {
		return true
	}
	if strings.Contains(profileArgs[0], dynamicpathdetector.DynamicIdentifier) {
		return dynamicpathdetector.CompareExecArgs(profileArgs, runtimeArgs)
	}
	if argv0Name(profileArgs[0]) != argv0Name(runtimeArgs[0]) {
		return false
	}
	if len(profileArgs) == 1 {
		return len(runtimeArgs) == 1
	}
	return dynamicpathdetector.CompareExecArgs(profileArgs[1:], runtimeArgs[1:])
}

// argv0Name returns the basename of argv[0] without a leading "-".
func argv0Name(arg0 string) string {
	return path.Base(strings.TrimPrefix(arg0, "-"))
}

func (l *containerProfileLibrary) isExecInPodSpec(containerID, path ref.Val) ref.Val {
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
					if slices.Contains(container.Command, pathStr) {
						return types.Bool(true)
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PreStop.Exec.Command, pathStr) {
							if l.preStopCache != nil {
								l.preStopCache.MarkPreStopTriggered(containerIDStr)
							}
							return types.Bool(true)
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PostStart.Exec.Command, pathStr) {
							return types.Bool(true)
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
					if slices.Contains(container.Command, pathStr) {
						return types.Bool(true)
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PreStop.Exec.Command, pathStr) {
							if l.preStopCache != nil {
								l.preStopCache.MarkPreStopTriggered(containerIDStr)
							}
							return types.Bool(true)
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PostStart.Exec.Command, pathStr) {
							return types.Bool(true)
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
					if slices.Contains(container.Command, pathStr) {
						return types.Bool(true)
					}
				}
				if container.Lifecycle != nil {
					if container.Lifecycle.PreStop != nil && container.Lifecycle.PreStop.Exec != nil && container.Lifecycle.PreStop.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PreStop.Exec.Command, pathStr) {
							if l.preStopCache != nil {
								l.preStopCache.MarkPreStopTriggered(containerIDStr)
							}
							return types.Bool(true)
						}
					}
					if container.Lifecycle.PostStart != nil && container.Lifecycle.PostStart.Exec != nil && container.Lifecycle.PostStart.Exec.Command != nil {
						if slices.Contains(container.Lifecycle.PostStart.Exec.Command, pathStr) {
							return types.Bool(true)
						}
					}
				}
				return types.Bool(false)
			}
		}
	}

	return types.Bool(false)
}
