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

func (c *KmodAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
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
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"module":  module,
		"syscall": kmodEvent.GetSyscall(),
		"exePath": exePath,
	}
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

func (c *KmodAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//kmodEvent, ok := enrichedEvent.Event.(*tracerkmodtype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&kmodEvent.Event)

	//result["pid"] = kmodEvent.Pid
	//result["tid"] = kmodEvent.Tid
	//result["ppid"] = kmodEvent.PPid
	//result["uid"] = kmodEvent.Uid
	//result["gid"] = kmodEvent.Gid
	//result["upperlayer"] = kmodEvent.UpperLayer
	//result["comm"] = kmodEvent.Comm
	//result["exe_path"] = kmodEvent.ExePath
	//result["module"] = kmodEvent.Module
	//result["syscall"] = kmodEvent.Syscall

	//result["mountnsid"] = kmodEvent.MountNsID

	return map[string]interface{}{}
}
