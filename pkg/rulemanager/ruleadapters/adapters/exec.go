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

func (c *ExecAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	execEvent, ok := enrichedEvent.Event.(*utils.DatasourceEvent)
	if !ok || execEvent.EventType != utils.ExecveEventType {
		return
	}

	failure.SetExtra(execEvent.GetExtra())

	execPath := execEvent.GetExecPathFromEvent()
	execFullPath := execEvent.GetExecFullPathFromEvent()
	upperLayer := execEvent.GetUpperLayer() || execEvent.GetPupperLayer()

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = execEvent.GetPID()
	baseRuntimeAlert.Arguments = map[string]interface{}{
		//"retval": execEvent.GetRetval(), // TODO this is missing in execEvent?
		"exec": execPath,
		"args": execEvent.GetArgs(),
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name:        execEvent.GetComm(),
			CommandLine: fmt.Sprintf("%s %s", execPath, strings.Join(execEvent.GetExecArgsFromEvent(), " ")),
		},
		File: &common.FileEntity{
			Name:      filepath.Base(execFullPath),
			Directory: filepath.Dir(execFullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       execEvent.GetComm(),
			Gid:        execEvent.GetGid(),
			PID:        execEvent.GetPID(),
			Uid:        execEvent.GetUid(),
			UpperLayer: &upperLayer,
			PPID:       execEvent.GetPpid(),
			Pcomm:      execEvent.GetPcomm(),
			Cwd:        execEvent.GetCwd(),
			Hardlink:   execEvent.GetExePath(),
			Path:       execFullPath,
			Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(execEvent.GetExecArgsFromEvent(), " ")),
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

func (c *ExecAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//execEvent, ok := enrichedEvent.Event.(*events.ExecEvent)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&execEvent.Event.Event)

	//result["pid"] = execEvent.Pid
	//result["tid"] = execEvent.Tid
	//result["ppid"] = execEvent.Ppid
	//result["ptid"] = execEvent.Ptid
	//result["comm"] = execEvent.Comm
	//result["pcomm"] = execEvent.Pcomm
	//result["ret"] = execEvent.Retval
	//result["args"] = execEvent.Args
	//result["uid"] = execEvent.Uid
	//result["user"] = execEvent.Username
	//result["gid"] = execEvent.Gid
	//result["group"] = execEvent.Groupname
	//result["upperlayer"] = execEvent.UpperLayer
	//result["pupperlayer"] = execEvent.PupperLayer
	//result["loginuid"] = execEvent.LoginUid
	//result["sessionid"] = execEvent.SessionId
	//result["cwd"] = execEvent.Cwd
	//result["exepath"] = execEvent.ExePath
	//result["file"] = execEvent.File

	//result["mountnsid"] = execEvent.MountNsID

	return map[string]interface{}{}
}
