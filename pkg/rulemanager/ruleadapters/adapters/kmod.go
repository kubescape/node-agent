package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type KmodAdapter struct {
}

func NewKmodAdapter() *KmodAdapter {
	return &KmodAdapter{}
}

func (c *KmodAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	kmodEvent, ok := enrichedEvent.Event.(utils.KmodEvent)
	if !ok {
		return
	}

	failure.SetExtra(kmodEvent.GetExtra())

	pid := kmodEvent.GetPID()
	comm := kmodEvent.GetComm()
	exePath := kmodEvent.GetExePath()
	module := kmodEvent.GetModule()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["module"] = module
	baseRuntimeAlert.Arguments["syscall"] = kmodEvent.GetSyscall()
	baseRuntimeAlert.Arguments["exePath"] = exePath
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	upperLayer := kmodEvent.GetUpperLayer()
	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       comm,
			Pcomm:      kmodEvent.GetPcomm(),
			PPID:       kmodEvent.GetPpid(),
			PID:        pid,
			UpperLayer: &upperLayer,
			Uid:        kmodEvent.GetUid(),
			Gid:        kmodEvent.GetGid(),
			Hardlink:   exePath,
			Path:       exePath,
		},
		ContainerID: kmodEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(kmodEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   kmodEvent.GetPod(),
		PodLabels: kmodEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
