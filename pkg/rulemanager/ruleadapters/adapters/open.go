package adapters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type OpenAdapter struct {
}

func NewOpenAdapter() *OpenAdapter {
	return &OpenAdapter{}
}

func (c *OpenAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	openEvent, ok := enrichedEvent.Event.(*events.OpenEvent)
	if !ok {
		return
	}

	openEventTyped := openEvent.Event

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = openEventTyped.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"flags": openEventTyped.Flags,
		"path":  openEventTyped.FullPath,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: openEventTyped.Comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(openEventTyped.FullPath),
			Directory: filepath.Dir(openEventTyped.FullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: openEventTyped.Comm,
			Gid:  &openEventTyped.Gid,
			PID:  openEventTyped.Pid,
			Uid:  &openEventTyped.Uid,
		},
		ContainerID: openEventTyped.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(openEventTyped.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: openEventTyped.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *OpenAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	// TODO: Implement ToMap functionality
	return nil
}
