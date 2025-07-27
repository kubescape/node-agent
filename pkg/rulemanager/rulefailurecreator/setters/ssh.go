package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type SSHFailureSetter struct {
}

func NewSSHCreator() *SSHFailureSetter {
	return &SSHFailureSetter{}
}

func (c *SSHFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	sshEvent, ok := enrichedEvent.Event.(*tracersshtype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = sshEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"src_ip":   sshEvent.SrcIP,
		"dst_ip":   sshEvent.DstIP,
		"src_port": sshEvent.SrcPort,
		"dst_port": sshEvent.DstPort,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: sshEvent.Comm,
		},
		Network: &common.NetworkEntity{
			DstIP:    sshEvent.DstIP,
			DstPort:  int(sshEvent.DstPort),
			Protocol: "ssh",
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: sshEvent.Comm,
			PID:  sshEvent.Pid,
			Uid:  &sshEvent.Uid,
			Gid:  &sshEvent.Gid,
		},
		ContainerID: sshEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(sshEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   sshEvent.GetPod(),
		PodLabels: sshEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
