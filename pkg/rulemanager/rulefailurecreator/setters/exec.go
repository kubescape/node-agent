package setters

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type ExecFailureSetter struct {
}

func NewExecCreator() *ExecFailureSetter {
	return &ExecFailureSetter{}
}

func (c *ExecFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	execEvent, ok := enrichedEvent.Event.(*events.ExecEvent)
	if !ok {
		return
	}

	execPath := GetExecPathFromEvent(execEvent)
	execFullPath := GetExecFullPathFromEvent(execEvent)
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = execEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"retval": execEvent.Retval,
		"exec":   execPath,
		"args":   execEvent.Args,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name:        execEvent.Comm,
			CommandLine: fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
		},
		File: &common.FileEntity{
			Name:      filepath.Base(execFullPath),
			Directory: filepath.Dir(execFullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       execEvent.Comm,
			Gid:        &execEvent.Gid,
			PID:        execEvent.Pid,
			Uid:        &execEvent.Uid,
			UpperLayer: &upperLayer,
			PPID:       execEvent.Ppid,
			Pcomm:      execEvent.Pcomm,
			Cwd:        execEvent.Cwd,
			Hardlink:   execEvent.ExePath,
			Path:       execFullPath,
			Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
		},
		ContainerID: execEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(execEvent.Event.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   execEvent.GetPod(),
		PodLabels: execEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

// Helper functions from the rule engine
func GetExecPathFromEvent(execEvent *events.ExecEvent) string {
	if len(execEvent.Args) > 0 {
		return execEvent.Args[0]
	}
	return execEvent.Comm
}

func GetExecFullPathFromEvent(execEvent *events.ExecEvent) string {
	if execEvent.ExePath != "" {
		return execEvent.ExePath
	}
	return GetExecPathFromEvent(execEvent)
}
