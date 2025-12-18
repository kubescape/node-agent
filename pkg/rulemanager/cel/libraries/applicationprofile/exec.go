package applicationprofile

import (
	"slices"

	"github.com/google/cel-go/common/types"

	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/celparse"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
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

	container, _, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, exec := range container.Execs {
		if exec.Path == pathStr {
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

	celArgs, err := celparse.ParseList[string](args)
	if err != nil {
		return types.NewErr("failed to parse args: %v", err)
	}

	container, _, err := profilehelper.GetContainerApplicationProfile(l.objectCache, containerIDStr)
	if err != nil {
		return types.Bool(false)
	}

	for _, exec := range container.Execs {
		if exec.Path == pathStr {
			if slices.Compare(exec.Args, celArgs) == 0 {
				return types.Bool(true)
			}
		}
	}

	if l.isExecInPodSpec(containerID, path).Value().(bool) {
		return types.Bool(true)
	}

	return types.Bool(false)
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
			}
		}
	}

	return types.Bool(false)
}
