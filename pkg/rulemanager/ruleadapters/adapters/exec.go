package adapters

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type ExecAdapter struct {
}

func NewExecAdapter() *ExecAdapter {
	return &ExecAdapter{}
}

func (c *ExecAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	execEvent, ok := enrichedEvent.Event.(*events.ExecEvent)
	if !ok {
		return
	}

	failure.SetExtra(execEvent.GetExtra())

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

func (c *ExecAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	execEvent, ok := enrichedEvent.Event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	result := ConvertToMap(&execEvent.Event.Event)

	result["pid"] = execEvent.Pid
	result["tid"] = execEvent.Tid
	result["ppid"] = execEvent.Ppid
	result["ptid"] = execEvent.Ptid
	result["comm"] = execEvent.Comm
	result["pcomm"] = execEvent.Pcomm
	result["ret"] = execEvent.Retval
	result["args"] = execEvent.Args
	result["uid"] = execEvent.Uid
	result["user"] = execEvent.Username
	result["gid"] = execEvent.Gid
	result["group"] = execEvent.Groupname
	result["upperlayer"] = execEvent.UpperLayer
	result["pupperlayer"] = execEvent.PupperLayer
	result["loginuid"] = execEvent.LoginUid
	result["sessionid"] = execEvent.SessionId
	result["cwd"] = execEvent.Cwd
	result["exepath"] = execEvent.ExePath
	result["file"] = execEvent.File

	result["mountnsid"] = execEvent.MountNsID

	return result
}
