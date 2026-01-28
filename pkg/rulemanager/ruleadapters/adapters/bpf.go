package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type BpfAdapter struct {
}

func NewBpfAdapter() *BpfAdapter {
	return &BpfAdapter{}
}

func (c *BpfAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	bpfEvent, ok := enrichedEvent.Event.(utils.BpfEvent)
	if !ok {
		return
	}

	failure.SetExtra(bpfEvent.GetExtra())

	pid := bpfEvent.GetPID()
	comm := bpfEvent.GetComm()
	exePath := bpfEvent.GetExePath()
	cmd := bpfEvent.GetCmd()
	attrSize := bpfEvent.GetAttrSize()
	upperLayer := bpfEvent.GetUpperLayer()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["cmd"] = cmd
	baseRuntimeAlert.Arguments["attrSize"] = attrSize
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
			Pcomm:      bpfEvent.GetPcomm(),
			PPID:       bpfEvent.GetPpid(),
			PID:        pid,
			UpperLayer: &upperLayer,
			Uid:        bpfEvent.GetUid(),
			Gid:        bpfEvent.GetGid(),
			Hardlink:   exePath,
			Path:       exePath,
		},
		ContainerID: bpfEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(bpfEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   bpfEvent.GetPod(),
		PodLabels: bpfEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

