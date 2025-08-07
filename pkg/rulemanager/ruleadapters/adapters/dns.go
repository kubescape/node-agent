package adapters

import (
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type DnsAdapter struct {
}

func NewDnsAdapter() *DnsAdapter {
	return &DnsAdapter{}
}

func (c *DnsAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	dnsEvent, ok := enrichedEvent.Event.(*tracerdnstype.Event)
	if !ok {
		return
	}

	dstIP := ""
	if len(dnsEvent.Addresses) > 0 {
		dstIP = dnsEvent.Addresses[0]
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = dnsEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"domain":    dnsEvent.DNSName,
		"addresses": dnsEvent.Addresses,
		"protocol":  dnsEvent.Protocol,
		"port":      dnsEvent.DstPort,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: dnsEvent.Comm,
		},
		Dns: &common.DnsEntity{
			Domain: dnsEvent.DNSName,
		},
		Network: &common.NetworkEntity{
			DstIP:    dstIP,
			Protocol: dnsEvent.Protocol,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:  dnsEvent.Comm,
			Gid:   &dnsEvent.Gid,
			PID:   dnsEvent.Pid,
			Uid:   &dnsEvent.Uid,
			Pcomm: dnsEvent.Pcomm,
			Path:  dnsEvent.Exepath,
			Cwd:   dnsEvent.Cwd,
			PPID:  dnsEvent.Ppid,
		},
		ContainerID: dnsEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(dnsEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   dnsEvent.GetPod(),
		PodLabels: dnsEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *DnsAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	dnsEvent, ok := enrichedEvent.Event.(*tracerdnstype.Event)
	if !ok {
		return nil
	}

	result := ConvertToMap(&dnsEvent.Event)

	result["pid"] = dnsEvent.Pid
	result["tid"] = dnsEvent.Tid
	result["ppid"] = dnsEvent.Ppid
	result["comm"] = dnsEvent.Comm
	result["pcomm"] = dnsEvent.Pcomm
	result["cwd"] = dnsEvent.Cwd
	result["exepath"] = dnsEvent.Exepath
	result["uid"] = dnsEvent.Uid
	result["gid"] = dnsEvent.Gid
	result["srcIP"] = dnsEvent.SrcIP
	result["dstIP"] = dnsEvent.DstIP
	result["srcPort"] = dnsEvent.SrcPort
	result["dstPort"] = dnsEvent.DstPort
	result["protocol"] = dnsEvent.Protocol
	result["id"] = dnsEvent.ID
	result["qr"] = dnsEvent.Qr
	result["nameserver"] = dnsEvent.Nameserver
	result["pktType"] = dnsEvent.PktType
	result["qtype"] = dnsEvent.QType
	result["name"] = dnsEvent.DNSName
	result["rcode"] = dnsEvent.Rcode
	result["latency"] = dnsEvent.Latency
	result["numAnswers"] = dnsEvent.NumAnswers
	result["addresses"] = dnsEvent.Addresses

	result["mountnsid"] = dnsEvent.MountNsID

	return result
}
