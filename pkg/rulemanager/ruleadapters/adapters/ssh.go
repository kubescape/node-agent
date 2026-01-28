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

func (c *SSHAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	sshEvent, ok := enrichedEvent.Event.(utils.SshEvent)
	if !ok {
		return
	}

	pid := sshEvent.GetPID()
	comm := sshEvent.GetComm()
	dstIP := sshEvent.GetDstIP()
	dstPort := sshEvent.GetDstPort()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["src_ip"] = sshEvent.GetSrcIP()
	baseRuntimeAlert.Arguments["dst_ip"] = dstIP
	baseRuntimeAlert.Arguments["src_port"] = sshEvent.GetSrcPort()
	baseRuntimeAlert.Arguments["dst_port"] = dstPort
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

