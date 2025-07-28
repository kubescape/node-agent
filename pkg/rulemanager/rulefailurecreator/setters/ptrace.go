package setters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type PtraceFailureSetter struct {
}

func NewPtraceCreator() *PtraceFailureSetter {
	return &PtraceFailureSetter{}
}

func (c *PtraceFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	ptraceEvent, ok := enrichedEvent.Event.(*tracerptracetype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = ptraceEvent.Pid
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: ptraceEvent.Comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(ptraceEvent.ExePath),
			Directory: filepath.Dir(ptraceEvent.ExePath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: ptraceEvent.Comm,
			PPID: ptraceEvent.PPid,
			PID:  ptraceEvent.Pid,
			Uid:  &ptraceEvent.Uid,
			Gid:  &ptraceEvent.Gid,
			Path: ptraceEvent.ExePath,
		},
		ContainerID: ptraceEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(ptraceEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   ptraceEvent.GetPod(),
		PodLabels: ptraceEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
