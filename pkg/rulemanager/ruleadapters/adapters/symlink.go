package adapters

import (
	"path/filepath"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type SymlinkAdapter struct {
}

func NewSymlinkAdapter() *SymlinkAdapter {
	return &SymlinkAdapter{}
}

func (c *SymlinkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	symlinkEvent, ok := enrichedEvent.Event.(utils.LinkEvent)
	if !ok {
		return
	}

	failure.SetExtra(symlinkEvent.GetExtra())

	pid := symlinkEvent.GetPID()
	comm := symlinkEvent.GetComm()
	exePath := symlinkEvent.GetExePath()
	oldPath := symlinkEvent.GetOldPath()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["oldPath"] = oldPath
	baseRuntimeAlert.Arguments["newPath"] = symlinkEvent.GetNewPath()
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

	upperLayer := symlinkEvent.GetUpperLayer()
	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       comm,
			PPID:       symlinkEvent.GetPpid(),
			PID:        pid,
			UpperLayer: &upperLayer,
			Uid:        symlinkEvent.GetUid(),
			Gid:        symlinkEvent.GetGid(),
			Hardlink:   exePath,
			Path:       exePath,
		},
		ContainerID: symlinkEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(symlinkEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   symlinkEvent.GetPod(),
		PodLabels: symlinkEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

