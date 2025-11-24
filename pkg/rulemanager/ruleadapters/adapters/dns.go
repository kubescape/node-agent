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

func (c *DnsAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	dnsEvent, ok := enrichedEvent.Event.(utils.DNSEvent)
	if !ok {
		return
	}

	dstIP := ""
	if addresses := dnsEvent.GetAddresses(); len(addresses) > 0 {
		dstIP = addresses[0]
	}

	pid := dnsEvent.GetPID()
	comm := dnsEvent.GetComm()
	dnsName := dnsEvent.GetDNSName()
	proto := dnsEvent.GetProto()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"domain":    dnsName,
		"addresses": dnsEvent.GetAddresses(),
		"protocol":  proto,
		"port":      dnsEvent.GetDstPort(),
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		Dns: &common.DnsEntity{
			Domain: dnsName,
		},
		Network: &common.NetworkEntity{
			DstIP:    dstIP,
			Protocol: proto,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:  comm,
			Gid:   dnsEvent.GetGid(),
			PID:   pid,
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
