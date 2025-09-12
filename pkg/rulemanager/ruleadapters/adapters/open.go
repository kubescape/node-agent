package adapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type OpenAdapter struct {
}

func NewOpenAdapter() *OpenAdapter {
	return &OpenAdapter{}
}

func (c *OpenAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	//openEvent, ok := enrichedEvent.Event.(*events.OpenEvent)
	//if !ok {
	//	return
	//}

	//failure.SetExtra(openEvent.GetExtra())

	//openEventTyped := openEvent.Event

	//baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	//baseRuntimeAlert.InfectedPID = openEventTyped.Pid
	//baseRuntimeAlert.Arguments = map[string]interface{}{
	//	"flags": openEventTyped.Flags,
	//	"path":  openEventTyped.FullPath,
	//}
	//baseRuntimeAlert.Identifiers = &common.Identifiers{
	//	Process: &common.ProcessEntity{
	//		Name: openEventTyped.Comm,
	//	},
	//	File: &common.FileEntity{
	//		Name:      filepath.Base(openEventTyped.FullPath),
	//		Directory: filepath.Dir(openEventTyped.FullPath),
	//	},
	//}
	//failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	//runtimeProcessDetails := apitypes.ProcessTree{
	//	ProcessTree: apitypes.Process{
	//		Comm: openEventTyped.Comm,
	//		Gid:  &openEventTyped.Gid,
	//		PID:  openEventTyped.Pid,
	//		Uid:  &openEventTyped.Uid,
	//	},
	//	ContainerID: openEventTyped.Runtime.ContainerID,
	//}
	//failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	//failure.SetTriggerEvent(openEventTyped.Event)

	//runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
	//	PodName: openEventTyped.GetPod(),
	//}
	//failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *OpenAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//openEvent, ok := enrichedEvent.Event.(*events.OpenEvent)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&openEvent.Event.Event)

	//result["pid"] = openEvent.Pid
	//result["tid"] = openEvent.Tid
	//result["uid"] = openEvent.Uid
	//result["gid"] = openEvent.Gid
	//result["comm"] = openEvent.Comm
	//result["fd"] = openEvent.Fd
	//result["err"] = openEvent.Err
	//result["flags"] = openEvent.Flags
	//result["flagsRaw"] = openEvent.FlagsRaw
	//result["mode"] = openEvent.Mode
	//result["modeRaw"] = openEvent.ModeRaw
	//result["path"] = openEvent.Path
	//result["fullPath"] = openEvent.FullPath

	//result["mountnsid"] = openEvent.MountNsID

	return map[string]interface{}{}
}
