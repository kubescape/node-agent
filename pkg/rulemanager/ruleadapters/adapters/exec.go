package adapters

import (
	"fmt"
	"path/filepath"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
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
	upperLayer := execEvent.GetUpperLayer() || execEvent.GetPupperLayer()

	pid := execEvent.GetPID()
	comm := execEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["exec"] = execPath
	baseRuntimeAlert.Arguments["args"] = execEvent.GetArgs()
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name:        comm,
			CommandLine: fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
		},
		File: &common.FileEntity{
			Name:      filepath.Base(execFullPath),
			Directory: filepath.Dir(execFullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
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
			Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
		},
		ContainerID: execEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(execEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   execEvent.GetPod(),
		PodLabels: execEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func GetExecFullPathFromEvent(execEvent utils.ExecEvent) string {
	if path := execEvent.GetExePath(); path != "" {
		return path
	}
	return utils.GetExecPathFromEvent(execEvent)
}

