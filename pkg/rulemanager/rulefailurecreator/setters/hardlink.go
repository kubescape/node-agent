package setters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type HardlinkFailureSetter struct {
}

func NewHardlinkCreator() *HardlinkFailureSetter {
	return &HardlinkFailureSetter{}
}

func (c *HardlinkFailureSetter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
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
