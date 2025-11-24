package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type CapabilitiesAdapter struct {
}

func NewCapabilitiesAdapter() *CapabilitiesAdapter {
	return &CapabilitiesAdapter{}
}

func (c *CapabilitiesAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	capEvent, ok := enrichedEvent.Event.(utils.CapabilitiesEvent)
	if !ok {
		return
	}

	pid := capEvent.GetPID()
	comm := capEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"syscall":    capEvent.GetSyscall(),
		"capability": capEvent.GetCapability(),
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			Gid:  capEvent.GetGid(),
			PID:  pid,
			Uid:  capEvent.GetUid(),
		},
		ContainerID: capEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(capEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: capEvent.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *CapabilitiesAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//capEvent, ok := enrichedEvent.Event.(*tracercapabilitiestype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&capEvent.Event)

	//result["pid"] = capEvent.Pid
	//result["comm"] = capEvent.Comm
	//result["syscall"] = capEvent.Syscall
	//result["uid"] = capEvent.Uid
	//result["gid"] = capEvent.Gid
	//result["cap"] = capEvent.Cap
	//result["capName"] = capEvent.CapName
	//result["audit"] = capEvent.Audit
	//result["verdict"] = capEvent.Verdict
	//result["insetid"] = capEvent.InsetID
	//result["targetuserns"] = capEvent.TargetUserNs
	//result["currentuserns"] = capEvent.CurrentUserNs
	//result["caps"] = capEvent.Caps
	//result["capsNames"] = capEvent.CapsNames

	//result["mountnsid"] = capEvent.MountNsID

	return map[string]interface{}{}
}
