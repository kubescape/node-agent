package adapters

import (
	"path/filepath"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type HardlinkAdapter struct {
}

func NewHardlinkAdapter() *HardlinkAdapter {
	return &HardlinkAdapter{}
}

func (c *HardlinkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	hardlinkEvent, ok := enrichedEvent.Event.(utils.LinkEvent)
	if !ok {
		return
	}

	failure.SetExtra(hardlinkEvent.GetExtra())

	pid := hardlinkEvent.GetPID()
	comm := hardlinkEvent.GetComm()
	exePath := hardlinkEvent.GetExePath()
	oldPath := hardlinkEvent.GetOldPath()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["oldPath"] = oldPath
	baseRuntimeAlert.Arguments["newPath"] = hardlinkEvent.GetNewPath()
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(oldPath),
			Directory: filepath.Dir(oldPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	upperLayer := hardlinkEvent.GetUpperLayer()
	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       comm,
			PPID:       hardlinkEvent.GetPpid(),
			PID:        pid,
			UpperLayer: &upperLayer,
			Uid:        hardlinkEvent.GetUid(),
			Gid:        hardlinkEvent.GetGid(),
			Path:       exePath,
			Hardlink:   exePath,
		},
		ContainerID: hardlinkEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(hardlinkEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   hardlinkEvent.GetPod(),
		PodLabels: hardlinkEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

