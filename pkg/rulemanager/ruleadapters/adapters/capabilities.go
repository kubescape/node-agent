package adapters

import (
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type CapabilitiesAdapter struct {
}

func NewCapabilitiesAdapter() *CapabilitiesAdapter {
	return &CapabilitiesAdapter{}
}

func (c *CapabilitiesAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	capEvent, ok := enrichedEvent.Event.(*tracercapabilitiestype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = capEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"syscall":    capEvent.Syscall,
		"capability": capEvent.CapName,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: capEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: capEvent.Comm,
			Gid:  &capEvent.Gid,
			PID:  capEvent.Pid,
			Uid:  &capEvent.Uid,
		},
		ContainerID: capEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(capEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: capEvent.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *CapabilitiesAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	capEvent, ok := enrichedEvent.Event.(*tracercapabilitiestype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&capEvent.Event)

	// Add capabilities-specific fields using JSON tags as keys
	result["pid"] = capEvent.Pid
	result["comm"] = capEvent.Comm
	result["syscall"] = capEvent.Syscall
	result["uid"] = capEvent.Uid
	result["gid"] = capEvent.Gid
	result["cap"] = capEvent.Cap
	result["capName"] = capEvent.CapName
	result["audit"] = capEvent.Audit
	result["verdict"] = capEvent.Verdict
	result["insetid"] = capEvent.InsetID
	result["targetuserns"] = capEvent.TargetUserNs
	result["currentuserns"] = capEvent.CurrentUserNs
	result["caps"] = capEvent.Caps
	result["capsNames"] = capEvent.CapsNames

	// Add mount namespace ID
	result["mountnsid"] = capEvent.MountNsID

	return result
}
