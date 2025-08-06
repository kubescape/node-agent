package adapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type RandomXAdapter struct {
}

func NewRandomXAdapter() *RandomXAdapter {
	return &RandomXAdapter{}
}

func (c *RandomXAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	randomXEvent, ok := enrichedEvent.Event.(*tracerrandomxtype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = randomXEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"ppid": randomXEvent.PPid,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: randomXEvent.Comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: randomXEvent.Comm,
			PID:  randomXEvent.Pid,
			Uid:  &randomXEvent.Uid,
			Gid:  &randomXEvent.Gid,
		},
		ContainerID: randomXEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(randomXEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   randomXEvent.GetPod(),
		PodLabels: randomXEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *RandomXAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	randomXEvent, ok := enrichedEvent.Event.(*tracerrandomxtype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&randomXEvent.Event)

	// Add RandomX-specific fields using JSON tags as keys
	result["pid"] = randomXEvent.Pid
	result["ppid"] = randomXEvent.PPid
	result["uid"] = randomXEvent.Uid
	result["gid"] = randomXEvent.Gid
	result["upperlayer"] = randomXEvent.UpperLayer
	result["comm"] = randomXEvent.Comm
	result["exe_path"] = randomXEvent.ExePath

	// Add mount namespace ID
	result["mountnsid"] = randomXEvent.MountNsID

	return result
}
