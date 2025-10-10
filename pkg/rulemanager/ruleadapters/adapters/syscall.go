package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type SyscallAdapter struct {
}

func NewSyscallAdapter() *SyscallAdapter {
	return &SyscallAdapter{}
}

func (c *SyscallAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	syscallEvent, ok := enrichedEvent.Event.(utils.EverythingEvent)
	if !ok || enrichedEvent.EventType != utils.SyscallEventType {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = syscallEvent.GetPID()
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"syscall": syscallEvent.GetSyscalls(), // TODO: is it ok as an array?
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: syscallEvent.GetComm(),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: syscallEvent.GetComm(),
			Gid:  syscallEvent.GetGid(),
			PID:  syscallEvent.GetPID(),
			Uid:  syscallEvent.GetUid(),
		},
		ContainerID: syscallEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(syscallEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   syscallEvent.GetPod(),
		PodLabels: syscallEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *SyscallAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//syscallEvent, ok := enrichedEvent.Event.(*types.SyscallEvent)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&syscallEvent.Event)

	//result["pid"] = syscallEvent.Pid
	//result["comm"] = syscallEvent.Comm
	//result["uid"] = syscallEvent.Uid
	//result["gid"] = syscallEvent.Gid
	//result["syscallName"] = syscallEvent.SyscallName

	//result["mountnsid"] = syscallEvent.MountNsID

	return map[string]interface{}{}
}
