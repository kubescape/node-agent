package adapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type CapabilitiesAdapter struct {
}

func NewCapabilitiesAdapter() *CapabilitiesAdapter {
	return &CapabilitiesAdapter{}
}

func (c *CapabilitiesAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	//capEvent, ok := enrichedEvent.Event.(*tracercapabilitiestype.Event)
	//if !ok {
	//	return
	//}

	//baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	//baseRuntimeAlert.InfectedPID = capEvent.Pid
	//baseRuntimeAlert.Arguments = map[string]interface{}{
	//	"syscall":    capEvent.Syscall,
	//	"capability": capEvent.CapName,
	//}
	//baseRuntimeAlert.Identifiers = &common.Identifiers{
	//	Process: &common.ProcessEntity{
	//		Name: capEvent.Comm,
	//	},
	//}
	//failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	//runtimeProcessDetails := apitypes.ProcessTree{
	//	ProcessTree: apitypes.Process{
	//		Comm: capEvent.Comm,
	//		Gid:  &capEvent.Gid,
	//		PID:  capEvent.Pid,
	//		Uid:  &capEvent.Uid,
	//	},
	//	ContainerID: capEvent.Runtime.ContainerID,
	//}
	//failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	//failure.SetTriggerEvent(capEvent.Event)

	//runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
	//	PodName: capEvent.GetPod(),
	//}
	//failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
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
