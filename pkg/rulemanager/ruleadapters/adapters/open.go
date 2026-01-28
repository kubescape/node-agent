package adapters

import (
	"path/filepath"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type OpenAdapter struct {
}

func NewOpenAdapter() *OpenAdapter {
	return &OpenAdapter{}
}

func (c *OpenAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	openEvent, ok := enrichedEvent.Event.(utils.OpenEvent)
	if !ok {
		return
	}

	failure.SetExtra(openEvent.GetExtra())

	pid := openEvent.GetPID()
	comm := openEvent.GetComm()
	fullPath := openEvent.GetFullPath()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["flags"] = openEvent.GetFlags()
	baseRuntimeAlert.Arguments["path"] = fullPath
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(fullPath),
			Directory: filepath.Dir(fullPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			Gid:  openEvent.GetGid(),
			PID:  pid,
			Uid:  openEvent.GetUid(),
		},
		ContainerID: openEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(openEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName: openEvent.GetPod(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

