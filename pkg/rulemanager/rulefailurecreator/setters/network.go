package setters

import (
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type NetworkFailureSetter struct {
}

func NewNetworkCreator() *NetworkFailureSetter {
	return &NetworkFailureSetter{}
}

func (c *NetworkFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	networkEvent, ok := enrichedEvent.Event.(*tracernetworktype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = networkEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"ip":    networkEvent.DstEndpoint.Addr,
		"port":  networkEvent.Port,
		"proto": networkEvent.Proto,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: networkEvent.Comm,
		},
		Network: &common.NetworkEntity{
			DstIP:    networkEvent.DstEndpoint.Addr,
			DstPort:  int(networkEvent.Port),
			Protocol: networkEvent.Proto,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: networkEvent.Comm,
			Gid:  &networkEvent.Gid,
			PID:  networkEvent.Pid,
			Uid:  &networkEvent.Uid,
		},
		ContainerID: networkEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(networkEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   networkEvent.GetPod(),
		PodLabels: networkEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
