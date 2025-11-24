package adapters

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type ProcfsFailureSetter struct {
}

func NewProcfsCreator() *ProcfsFailureSetter {
	return &ProcfsFailureSetter{}
}

func (c *ProcfsFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, state map[string]any) {
	procfsEvent, ok := enrichedEvent.Event.(*events.ProcfsEvent)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = procfsEvent.PID
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"ppid":          procfsEvent.PPID,
		"start_time_ns": procfsEvent.StartTimeNs,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: procfsEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: procfsEvent.Comm,
			PID:  procfsEvent.PID,
			PPID: procfsEvent.PPID,
			Uid:  procfsEvent.Uid,
			Gid:  procfsEvent.Gid,
			Path: procfsEvent.Path,
		},
		ContainerID: procfsEvent.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	ruleAlert := apitypes.RuleAlert{
		RuleDescription: fmt.Sprintf("Procfs event detected for process %s (PID: %d)", procfsEvent.Comm, procfsEvent.PID),
	}
	failure.SetRuleAlert(ruleAlert)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: procfsEvent.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
