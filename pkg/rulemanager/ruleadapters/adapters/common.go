package adapters

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type RuntimeInfo struct {
	ContainerID          string
	ContainerName        string
	ContainerImageName   string
	ContainerImageDigest string
}

type K8sInfo struct {
	Namespace     string
	PodName       string
	PodLabels     map[string]string
	ContainerName string
	HostNetwork   bool
}

type EnrichEventResult struct {
	Timestamp types.Time
	Type      utils.EventType
	Runtime   RuntimeInfo
	K8s       K8sInfo
	PID       uint32
	UID       uint32
	GID       uint32
	OtherIP   string
	Internal  bool
	Direction consts.NetworkDirection
	MountNsID uint64
	//Request   *http.Request
	//Response  *http.Response
}

func ConvertToMap(e utils.HttpEvent) EnrichEventResult {
	return EnrichEventResult{
		Timestamp: e.GetTimestamp(),
		Type:      e.GetEventType(),
		Runtime: RuntimeInfo{
			ContainerID:          e.GetContainerID(),
			ContainerName:        e.GetContainer(),
			ContainerImageName:   e.GetContainerImage(),
			ContainerImageDigest: e.GetContainerImageDigest(),
		},
		K8s: K8sInfo{
			Namespace:     e.GetNamespace(),
			PodName:       e.GetPod(),
			PodLabels:     e.GetPodLabels(),
			ContainerName: e.GetContainer(),
			HostNetwork:   e.GetHostNetwork(),
		},
		PID:       e.GetPID(),
		UID:       *e.GetUid(),
		GID:       *e.GetGid(),
		OtherIP:   e.GetOtherIp(),
		Internal:  e.GetInternal(),
		Direction: e.GetDirection(),
		MountNsID: e.GetMountNsID(),
		//Request:   e.GetRequest(),
		//Response:  e.GetResponse(),
	}
}
