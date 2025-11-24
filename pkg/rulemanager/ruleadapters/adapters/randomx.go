package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RandomXAdapter struct {
}

func NewRandomXAdapter() *RandomXAdapter {
	return &RandomXAdapter{}
}

func (c *RandomXAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	randomXEvent, ok := enrichedEvent.Event.(utils.EnrichEvent)
	if !ok {
		return
	}

	pid := randomXEvent.GetPID()
	comm := randomXEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"ppid": randomXEvent.GetPpid(),
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			PID:  pid,
			Uid:  randomXEvent.GetUid(),
			Gid:  randomXEvent.GetGid(),
		},
		ContainerID: randomXEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(randomXEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   randomXEvent.GetPod(),
		PodLabels: randomXEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *RandomXAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//randomXEvent, ok := enrichedEvent.Event.(*tracerrandomxtype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&randomXEvent.Event)

	//result["pid"] = randomXEvent.Pid
	//result["ppid"] = randomXEvent.PPid
	//result["uid"] = randomXEvent.Uid
	//result["gid"] = randomXEvent.Gid
	//result["upperlayer"] = randomXEvent.UpperLayer
	//result["comm"] = randomXEvent.Comm
	//result["exe_path"] = randomXEvent.ExePath

	//result["mountnsid"] = randomXEvent.MountNsID

	return map[string]interface{}{}
}
