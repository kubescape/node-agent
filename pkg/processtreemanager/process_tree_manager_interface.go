package processtreemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

type TreeTracking struct {
	UniqueID uint32
	Sent     bool
}

type ProcessTreeManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportFileExec(event tracerexectype.Event)
}

type ProcessTreeManager interface {
	GetProcessTreeByContainerId(containerID string) *apitypes.Process
	GetTreeTrackingByContainerId(containerID string) *TreeTracking
	GetProcessByPid(containerID string, pid uint32) *apitypes.Process
}
