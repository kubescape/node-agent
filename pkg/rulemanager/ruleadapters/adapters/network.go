package adapters

import (
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type NetworkAdapter struct {
}

func NewNetworkAdapter() *NetworkAdapter {
	return &NetworkAdapter{}
}

func (c *NetworkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
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

func (c *NetworkAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	networkEvent, ok := enrichedEvent.Event.(*tracernetworktype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&networkEvent.Event)

	// Add network-specific fields using JSON tags as keys
	result["pid"] = networkEvent.Pid
	result["tid"] = networkEvent.Tid
	result["comm"] = networkEvent.Comm
	result["uid"] = networkEvent.Uid
	result["gid"] = networkEvent.Gid
	result["pktType"] = networkEvent.PktType
	result["proto"] = networkEvent.Proto
	result["port"] = networkEvent.Port
	result["podHostIP"] = networkEvent.PodHostIP
	result["podIP"] = networkEvent.PodIP
	result["podOwner"] = networkEvent.PodOwner
	result["podLabels"] = networkEvent.PodLabels

	// Add destination endpoint as nested structure
	dst := make(map[string]interface{})
	dst["addr"] = networkEvent.DstEndpoint.Addr
	dst["version"] = networkEvent.DstEndpoint.Version
	dst["namespace"] = networkEvent.DstEndpoint.Namespace
	dst["podname"] = networkEvent.DstEndpoint.Name
	dst["kind"] = networkEvent.DstEndpoint.Kind
	dst["podlabels"] = networkEvent.DstEndpoint.PodLabels
	result["dst"] = dst

	// Add mount namespace ID
	result["mountnsid"] = networkEvent.MountNsID

	return result
}
