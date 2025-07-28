package setters

import (
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type CapabilitiesFailureSetter struct {
}

func NewCapabilitiesCreator() *CapabilitiesFailureSetter {
	return &CapabilitiesFailureSetter{}
}

func (c *CapabilitiesFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
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
