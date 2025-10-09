package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type DnsAdapter struct {
}

func NewDnsAdapter() *DnsAdapter {
	return &DnsAdapter{}
}

func (c *DnsAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	dnsEvent, ok := enrichedEvent.Event.(*utils.DatasourceEvent)
	if !ok || dnsEvent.EventType != utils.DnsEventType {
		return
	}

	dstIP := ""
	if addresses := dnsEvent.GetAddresses(); len(addresses) > 0 {
		dstIP = addresses[0]
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = dnsEvent.GetPID()
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"domain":    dnsEvent.GetDNSName(),
		"addresses": dnsEvent.GetAddresses(),
		"protocol":  dnsEvent.GetProto(),
		"port":      dnsEvent.GetDstPort(),
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: dnsEvent.GetComm(),
		},
		Dns: &common.DnsEntity{
			Domain: dnsEvent.GetDNSName(),
		},
		Network: &common.NetworkEntity{
			DstIP:    dstIP,
			Protocol: dnsEvent.GetProto(),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:  dnsEvent.GetComm(),
			Gid:   dnsEvent.GetGid(),
			PID:   dnsEvent.GetPID(),
			Uid:   dnsEvent.GetUid(),
			Pcomm: dnsEvent.GetPcomm(),
			Path:  dnsEvent.GetExePath(),
			Cwd:   dnsEvent.GetCwd(),
			PPID:  dnsEvent.GetPpid(),
		},
		ContainerID: dnsEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(dnsEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   dnsEvent.GetPod(),
		PodLabels: dnsEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *DnsAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//dnsEvent, ok := enrichedEvent.Event.(*tracerdnstype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&dnsEvent.Event)

	//result["pid"] = dnsEvent.Pid
	//result["tid"] = dnsEvent.Tid
	//result["ppid"] = dnsEvent.Ppid
	//result["comm"] = dnsEvent.Comm
	//result["pcomm"] = dnsEvent.Pcomm
	//result["cwd"] = dnsEvent.Cwd
	//result["exepath"] = dnsEvent.Exepath
	//result["uid"] = dnsEvent.Uid
	//result["gid"] = dnsEvent.Gid
	//result["srcIP"] = dnsEvent.SrcIP
	//result["dstIP"] = dnsEvent.DstIP
	//result["srcPort"] = dnsEvent.SrcPort
	//result["dstPort"] = dnsEvent.DstPort
	//result["protocol"] = dnsEvent.Protocol
	//result["id"] = dnsEvent.ID
	//result["qr"] = dnsEvent.Qr
	//result["nameserver"] = dnsEvent.Nameserver
	//result["pktType"] = dnsEvent.PktType
	//result["qtype"] = dnsEvent.QType
	//result["name"] = dnsEvent.DNSName
	//result["rcode"] = dnsEvent.Rcode
	//result["latency"] = dnsEvent.Latency
	//result["numAnswers"] = dnsEvent.NumAnswers
	//result["addresses"] = dnsEvent.Addresses

	//result["mountnsid"] = dnsEvent.MountNsID

	return map[string]interface{}{}
}
