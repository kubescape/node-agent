package adapters

import (
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ExecAdapter struct {
}

func NewExecAdapter() *ExecAdapter {
	return &ExecAdapter{}
}

func (c *ExecAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	execEvent, ok := enrichedEvent.Event.(utils.ExecEvent)
	if !ok {
		return
	}

	failure.SetExtra(execEvent.GetExtra())

	execPath := utils.GetExecPathFromEvent(execEvent)
	execFullPath := GetExecFullPathFromEvent(execEvent)
	commandLine := execCommandLine(execEvent, execPath)
	upperLayer := execEvent.GetUpperLayer() || execEvent.GetPupperLayer()

	pid := execEvent.GetPID()
	comm := execEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]any)
	}
	baseRuntimeAlert.Arguments["exec"] = execPath
	baseRuntimeAlert.Arguments["args"] = execEvent.GetArgs()
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name:        comm,
			CommandLine: commandLine,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(execFullPath),
			Directory: filepath.Dir(execFullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := armotypes.ProcessTree{
		ProcessTree: armotypes.Process{
			Comm:       comm,
			Gid:        execEvent.GetGid(),
			PID:        pid,
			Uid:        execEvent.GetUid(),
			UpperLayer: &upperLayer,
			PPID:       execEvent.GetPpid(),
			Pcomm:      execEvent.GetPcomm(),
			Cwd:        execEvent.GetCwd(),
			Hardlink:   execEvent.GetExePath(),
			Path:       execFullPath,
			Cmdline:    commandLine,
		},
		ContainerID: execEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(execEvent)

	runtimeAlertK8sDetails := armotypes.RuntimeAlertK8sDetails{
		PodName:   execEvent.GetPod(),
		PodLabels: execEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

// execCommandLine joins the full argv, so argv[0] (a busybox applet name, for
// example) is kept. It falls back to the exec path when argv was not captured.
func execCommandLine(execEvent utils.ExecEvent, execPath string) string {
	if args := execEvent.GetArgs(); len(args) > 0 {
		return strings.Join(args, " ")
	}
	return execPath
}

func GetExecFullPathFromEvent(execEvent utils.ExecEvent) string {
	if path := execEvent.GetExePath(); path != "" {
		return path
	}
	return utils.GetExecPathFromEvent(execEvent)
}
