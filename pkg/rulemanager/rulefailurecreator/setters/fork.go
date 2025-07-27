package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerforktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type ForkFailureSetter struct {
}

func NewForkCreator() *ForkFailureSetter {
	return &ForkFailureSetter{}
}

func (c *ForkFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	forkEvent, ok := enrichedEvent.Event.(*tracerforktype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = forkEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"child_pid": forkEvent.ChildPid,
		"child_tid": forkEvent.ChildTid,
		"ppid":      forkEvent.PPid,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: forkEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: forkEvent.Comm,
			PID:  forkEvent.Pid,
			PPID: forkEvent.PPid,
			Uid:  &forkEvent.Uid,
			Gid:  &forkEvent.Gid,
			Path: forkEvent.ExePath,
		},
		ContainerID: forkEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(forkEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   forkEvent.GetPod(),
		PodLabels: forkEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
