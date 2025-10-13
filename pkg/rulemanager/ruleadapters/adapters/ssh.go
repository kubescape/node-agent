package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type SSHAdapter struct {
}

func NewSSHAdapter() *SSHAdapter {
	return &SSHAdapter{}
}

func (c *SSHAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	sshEvent, ok := enrichedEvent.Event.(utils.EverythingEvent)
	if !ok || enrichedEvent.EventType != utils.SSHEventType {
		return
	}

	pid := sshEvent.GetPID()
	comm := sshEvent.GetComm()
	dstIP := sshEvent.GetDstIP()
	dstPort := sshEvent.GetDstPort()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"src_ip":   sshEvent.GetSrcIP(),
		"dst_ip":   dstIP,
		"src_port": sshEvent.GetSrcPort(),
		"dst_port": dstPort,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		Network: &common.NetworkEntity{
			DstIP:    dstIP,
			DstPort:  int(dstPort),
			Protocol: "ssh",
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			PID:  pid,
			Uid:  sshEvent.GetUid(),
			Gid:  sshEvent.GetGid(),
		},
		ContainerID: sshEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(sshEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   sshEvent.GetPod(),
		PodLabels: sshEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *SSHAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//sshEvent, ok := enrichedEvent.Event.(*tracersshtype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&sshEvent.Event)

	//result["pid"] = sshEvent.Pid
	//result["uid"] = sshEvent.Uid
	//result["gid"] = sshEvent.Gid
	//result["comm"] = sshEvent.Comm
	//result["src_port"] = sshEvent.SrcPort
	//result["dst_port"] = sshEvent.DstPort
	//result["src_ip"] = sshEvent.SrcIP
	//result["dst_ip"] = sshEvent.DstIP

	//result["mountnsid"] = sshEvent.MountNsID

	return map[string]interface{}{}
}
