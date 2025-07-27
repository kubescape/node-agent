package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type ExitFailureSetter struct {
}

func NewExitCreator() *ExitFailureSetter {
	return &ExitFailureSetter{}
}

func (c *ExitFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	exitEvent, ok := enrichedEvent.Event.(*tracerexittype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = exitEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"exit_code": exitEvent.ExitCode,
		"ppid":      exitEvent.PPid,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: exitEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: exitEvent.Comm,
			PID:  exitEvent.Pid,
			PPID: exitEvent.PPid,
			Uid:  &exitEvent.Uid,
			Gid:  &exitEvent.Gid,
			Path: exitEvent.ExePath,
		},
		ContainerID: exitEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(exitEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   exitEvent.GetPod(),
		PodLabels: exitEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
