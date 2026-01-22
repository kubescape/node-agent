package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type NetworkAdapter struct {
}

func NewNetworkAdapter() *NetworkAdapter {
	return &NetworkAdapter{}
}

func (c *NetworkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	networkEvent, ok := enrichedEvent.Event.(utils.NetworkEvent)
	if !ok {
		return
	}

	pid := networkEvent.GetPID()
	comm := networkEvent.GetComm()
	dstEndpoint := networkEvent.GetDstEndpoint()
	port := networkEvent.GetDstPort()
	proto := networkEvent.GetProto()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["ip"] = dstEndpoint.Addr
	baseRuntimeAlert.Arguments["port"] = port
	baseRuntimeAlert.Arguments["proto"] = proto
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		Network: &common.NetworkEntity{
			DstIP:    dstEndpoint.Addr,
			DstPort:  int(port),
			Protocol: proto,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			Gid:  networkEvent.GetGid(),
			PID:  pid,
			Uid:  networkEvent.GetUid(),
		},
		ContainerID: networkEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(networkEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   networkEvent.GetPod(),
		PodLabels: networkEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *NetworkAdapter) ToMap(enrichedEvent *events.EnrichedEvent) any {
	//networkEvent, ok := enrichedEvent.Event.(*tracernetworktype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&networkEvent.Event)

	//result["pid"] = networkEvent.Pid
	//result["tid"] = networkEvent.Tid
	//result["comm"] = networkEvent.Comm
	//result["uid"] = networkEvent.Uid
	//result["gid"] = networkEvent.Gid
	//result["pktType"] = networkEvent.PktType
	//result["proto"] = networkEvent.Proto
	//result["port"] = networkEvent.Port
	//result["podHostIP"] = networkEvent.PodHostIP
	//result["podIP"] = networkEvent.PodIP
	//result["podOwner"] = networkEvent.PodOwner
	//result["podLabels"] = networkEvent.PodLabels

	//dst := AcquireMap()
	//dst["addr"] = networkEvent.DstEndpoint.Addr
	//dst["version"] = networkEvent.DstEndpoint.Version
	//dst["namespace"] = networkEvent.DstEndpoint.Namespace
	//dst["podname"] = networkEvent.DstEndpoint.Name
	//dst["kind"] = networkEvent.DstEndpoint.Kind
	//dst["podlabels"] = networkEvent.DstEndpoint.PodLabels
	//result["dst"] = dst

	//result["mountnsid"] = networkEvent.MountNsID

	return nil
}
