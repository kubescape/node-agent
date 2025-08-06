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
	// TODO: Implement ToMap functionality
	return nil
}
