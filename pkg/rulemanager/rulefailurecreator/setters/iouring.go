package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1/helpers/iouring"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type IoUringFailureSetter struct {
}

func NewIoUringCreator() *IoUringFailureSetter {
	return &IoUringFailureSetter{}
}

func (c *IoUringFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	iouringEvent, ok := enrichedEvent.Event.(*traceriouringtype.Event)
	if !ok {
		return
	}

	ok, name := iouring.GetOpcodeName(uint8(iouringEvent.Opcode))
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = iouringEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"opcode":    iouringEvent.Opcode,
		"flags":     iouringEvent.Flags,
		"operation": name,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: iouringEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: iouringEvent.Comm,
			PID:  iouringEvent.Pid,
			Uid:  &iouringEvent.Uid,
			Gid:  &iouringEvent.Gid,
		},
		ContainerID: iouringEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(iouringEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   iouringEvent.GetPod(),
		PodLabels: iouringEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
