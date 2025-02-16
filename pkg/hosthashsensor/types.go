package hosthashsensor

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type FileHashResult interface {
	// Get Basic Runtime Alert
	GetBasicRuntimeAlert() apitypes.BaseRuntimeAlert
	// Get Runtime Process Details
	GetRuntimeProcessDetails() apitypes.ProcessTree
	// Get Trigger Event
	GetTriggerEvent() igtypes.Event
	// Get Malware Description
	GetMalwareRuntimeAlert() apitypes.MalwareAlert
	// Get K8s Runtime Details
	GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails
}
