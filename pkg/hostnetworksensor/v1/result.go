package hostnetworksensor

import (
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type NetworkScanResult struct {
	ScanResult     armotypes.NetworkScanAlert
	ProcessDetails armotypes.ProcessTree
	Timestamp      time.Time
	Pid            int
	Event          igtypes.Event
}

func (nsr NetworkScanResult) GetAlertType() armotypes.AlertType {
	return armotypes.AlertTypeNetworkScan
}

func (nsr NetworkScanResult) GetAlertName() string {
	return "NetworkScanResult"
}

func (nsr NetworkScanResult) GetBasicRuntimeAlert() armotypes.BaseRuntimeAlert {
	baseAlert := armotypes.BaseRuntimeAlert{
		AlertName:   "NetworkScanResult",
		Timestamp:   nsr.Timestamp,
		InfectedPID: uint32(nsr.Pid),
		Severity:    1,
	}
	return baseAlert
}

func (nsr NetworkScanResult) GetRuntimeProcessDetails() armotypes.ProcessTree {
	return nsr.ProcessDetails
}

func (nsr NetworkScanResult) GetTriggerEvent() igtypes.Event {
	return nsr.Event
}

func (nsr NetworkScanResult) GetNetworkScanAlert() armotypes.NetworkScanAlert {
	return nsr.ScanResult
}

func (nsr NetworkScanResult) GetRuntimeAlertK8sDetails() armotypes.RuntimeAlertK8sDetails {
	return armotypes.RuntimeAlertK8sDetails{
		ContainerID:   nsr.Event.Runtime.ContainerID,
		ContainerName: nsr.Event.K8s.ContainerName,
		Namespace:     nsr.Event.GetNamespace(),
		PodName:       nsr.Event.K8s.PodName,
		PodNamespace:  nsr.Event.GetNamespace(),
		HostNetwork:   &nsr.Event.K8s.HostNetwork,
		Image:         nsr.Event.Runtime.ContainerImageName,
		ImageDigest:   nsr.Event.Runtime.ContainerImageDigest,
	}
}
