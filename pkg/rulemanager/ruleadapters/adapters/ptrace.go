package adapters

import (
	"path/filepath"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type PtraceAdapter struct {
}

func NewPtraceAdapter() *PtraceAdapter {
	return &PtraceAdapter{}
}

func (c *PtraceAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	ptraceEvent, ok := enrichedEvent.Event.(utils.EverythingEvent)
	if !ok || enrichedEvent.EventType != utils.PtraceEventType {
		return
	}

	pid := ptraceEvent.GetPID()
	exePath := ptraceEvent.GetExePath()
	comm := ptraceEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(exePath),
			Directory: filepath.Dir(exePath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			PPID: ptraceEvent.GetPpid(),
			PID:  pid,
			Uid:  ptraceEvent.GetUid(),
			Gid:  ptraceEvent.GetGid(),
			Path: exePath,
		},
		ContainerID: ptraceEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(ptraceEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   ptraceEvent.GetPod(),
		PodLabels: ptraceEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *PtraceAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//ptraceEvent, ok := enrichedEvent.Event.(*tracerptracetype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&ptraceEvent.Event)

	//result["pid"] = ptraceEvent.Pid
	//result["ppid"] = ptraceEvent.PPid
	//result["uid"] = ptraceEvent.Uid
	//result["gid"] = ptraceEvent.Gid
	//result["request"] = ptraceEvent.Request
	//result["comm"] = ptraceEvent.Comm
	//result["exe_path"] = ptraceEvent.ExePath

	//result["mountnsid"] = ptraceEvent.MountNsID

	return map[string]interface{}{}
}
