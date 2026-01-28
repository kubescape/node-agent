package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type UnshareAdapter struct {
}

func NewUnshareAdapter() *UnshareAdapter {
	return &UnshareAdapter{}
}

func (c *UnshareAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	unshareEvent, ok := enrichedEvent.Event.(utils.UnshareEvent)
	if !ok {
		return
	}

	failure.SetExtra(unshareEvent.GetExtra())

	pid := unshareEvent.GetPID()
	comm := unshareEvent.GetComm()
	exePath := unshareEvent.GetExePath()
	upperLayer := unshareEvent.GetUpperLayer()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["exePath"] = exePath
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       comm,
			Pcomm:      unshareEvent.GetPcomm(),
			PPID:       unshareEvent.GetPpid(),
			PID:        pid,
			UpperLayer: &upperLayer,
			Uid:        unshareEvent.GetUid(),
			Gid:        unshareEvent.GetGid(),
			Hardlink:   exePath,
			Path:       exePath,
		},
		ContainerID: unshareEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(unshareEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   unshareEvent.GetPod(),
		PodLabels: unshareEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

