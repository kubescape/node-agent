package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type SyscallFailureSetter struct {
}

func NewSyscallCreator() *SyscallFailureSetter {
	return &SyscallFailureSetter{}
}

func (c *SyscallFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	syscallEvent, ok := enrichedEvent.Event.(*types.SyscallEvent)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = syscallEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"syscall": syscallEvent.SyscallName,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: syscallEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: syscallEvent.Comm,
			Gid:  &syscallEvent.Gid,
			PID:  syscallEvent.Pid,
			Uid:  &syscallEvent.Uid,
		},
		ContainerID: syscallEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(syscallEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   syscallEvent.GetPod(),
		PodLabels: syscallEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
