package adapters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type HardlinkAdapter struct {
}

func NewHardlinkAdapter() *HardlinkAdapter {
	return &HardlinkAdapter{}
}

func (c *HardlinkAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	hardlinkEvent, ok := enrichedEvent.Event.(*tracerhardlinktype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = hardlinkEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"oldPath": hardlinkEvent.OldPath,
		"newPath": hardlinkEvent.NewPath,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: hardlinkEvent.Comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(hardlinkEvent.OldPath),
			Directory: filepath.Dir(hardlinkEvent.OldPath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm:       hardlinkEvent.Comm,
			PPID:       hardlinkEvent.PPid,
			PID:        hardlinkEvent.Pid,
			UpperLayer: &hardlinkEvent.UpperLayer,
			Uid:        &hardlinkEvent.Uid,
			Gid:        &hardlinkEvent.Gid,
			Path:       hardlinkEvent.ExePath,
			Hardlink:   hardlinkEvent.ExePath,
		},
		ContainerID: hardlinkEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(hardlinkEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   hardlinkEvent.GetPod(),
		PodLabels: hardlinkEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *HardlinkAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	hardlinkEvent, ok := enrichedEvent.Event.(*tracerhardlinktype.Event)
	if !ok {
		return nil
	}

	result := ConvertToMap(&hardlinkEvent.Event)

	result["pid"] = hardlinkEvent.Pid
	result["tid"] = hardlinkEvent.Tid
	result["ppid"] = hardlinkEvent.PPid
	result["uid"] = hardlinkEvent.Uid
	result["gid"] = hardlinkEvent.Gid
	result["upperlayer"] = hardlinkEvent.UpperLayer
	result["comm"] = hardlinkEvent.Comm
	result["exe_path"] = hardlinkEvent.ExePath
	result["oldpath"] = hardlinkEvent.OldPath
	result["newpath"] = hardlinkEvent.NewPath

	result["mountnsid"] = hardlinkEvent.MountNsID

	return result
}
