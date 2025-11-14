package adapters

import (
	"path/filepath"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type OpenAdapter struct {
}

func NewOpenAdapter() *OpenAdapter {
	return &OpenAdapter{}
}

func (c *OpenAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	openEvent, ok := enrichedEvent.Event.(utils.OpenEvent)
	if !ok {
		return
	}

	failure.SetExtra(openEvent.GetExtra())

	pid := openEvent.GetPID()
	comm := openEvent.GetComm()
	fullPath := openEvent.GetFullPath()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"flags": openEvent.GetFlags(),
		"path":  fullPath,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(fullPath),
			Directory: filepath.Dir(fullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			Gid:  openEvent.GetGid(),
			PID:  pid,
			Uid:  openEvent.GetUid(),
		},
		ContainerID: openEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(openEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: openEvent.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *OpenAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//openEvent, ok := enrichedEvent.Event.(*events.OpenEvent)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&openEvent.Event.Event)

	//result["pid"] = openEvent.Pid
	//result["tid"] = openEvent.Tid
	//result["uid"] = openEvent.Uid
	//result["gid"] = openEvent.Gid
	//result["comm"] = openEvent.Comm
	//result["fd"] = openEvent.Fd
	//result["err"] = openEvent.Err
	//result["flags"] = openEvent.Flags
	//result["flagsRaw"] = openEvent.FlagsRaw
	//result["mode"] = openEvent.Mode
	//result["modeRaw"] = openEvent.ModeRaw
	//result["path"] = openEvent.Path
	//result["fullPath"] = openEvent.FullPath

	//result["mountnsid"] = openEvent.MountNsID

	return map[string]interface{}{}
}
