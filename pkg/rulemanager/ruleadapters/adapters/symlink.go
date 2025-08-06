package adapters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type SymlinkAdapter struct {
}

func NewSymlinkAdapter() *SymlinkAdapter {
	return &SymlinkAdapter{}
}

func (c *SymlinkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	symlinkEvent, ok := enrichedEvent.Event.(*tracersymlinktype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = symlinkEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"oldPath": symlinkEvent.OldPath,
		"newPath": symlinkEvent.NewPath,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: symlinkEvent.Comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(symlinkEvent.OldPath),
			Directory: filepath.Dir(symlinkEvent.OldPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       symlinkEvent.Comm,
			PPID:       symlinkEvent.PPid,
			PID:        symlinkEvent.Pid,
			UpperLayer: &symlinkEvent.UpperLayer,
			Uid:        &symlinkEvent.Uid,
			Gid:        &symlinkEvent.Gid,
			Hardlink:   symlinkEvent.ExePath,
			Path:       symlinkEvent.ExePath,
		},
		ContainerID: symlinkEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(symlinkEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   symlinkEvent.GetPod(),
		PodLabels: symlinkEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *SymlinkAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	symlinkEvent, ok := enrichedEvent.Event.(*tracersymlinktype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&symlinkEvent.Event)

	// Add symlink-specific fields using JSON tags as keys
	result["pid"] = symlinkEvent.Pid
	result["tid"] = symlinkEvent.Tid
	result["ppid"] = symlinkEvent.PPid
	result["uid"] = symlinkEvent.Uid
	result["gid"] = symlinkEvent.Gid
	result["upperlayer"] = symlinkEvent.UpperLayer
	result["comm"] = symlinkEvent.Comm
	result["exe_path"] = symlinkEvent.ExePath
	result["oldpath"] = symlinkEvent.OldPath
	result["newpath"] = symlinkEvent.NewPath

	// Add mount namespace ID
	result["mountnsid"] = symlinkEvent.MountNsID

	return result
}
