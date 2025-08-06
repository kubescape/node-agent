package adapters

import (
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type PtraceAdapter struct {
}

func NewPtraceAdapter() *PtraceAdapter {
	return &PtraceAdapter{}
}

func (c *PtraceAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	ptraceEvent, ok := enrichedEvent.Event.(*tracerptracetype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = ptraceEvent.Pid
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: ptraceEvent.Comm,
		},
		File: &common.FileEntity{
			Name:      filepath.Base(ptraceEvent.ExePath),
			Directory: filepath.Dir(ptraceEvent.ExePath),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: ptraceEvent.Comm,
			PPID: ptraceEvent.PPid,
			PID:  ptraceEvent.Pid,
			Uid:  &ptraceEvent.Uid,
			Gid:  &ptraceEvent.Gid,
			Path: ptraceEvent.ExePath,
		},
		ContainerID: ptraceEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(ptraceEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   ptraceEvent.GetPod(),
		PodLabels: ptraceEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *PtraceAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	ptraceEvent, ok := enrichedEvent.Event.(*tracerptracetype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&ptraceEvent.Event)

	// Add ptrace-specific fields directly to the result map using JSON tags as keys
	// This allows CEL expressions to access fields like data.event.comm, data.event.pid, etc.
	result["pid"] = ptraceEvent.Pid
	result["ppid"] = ptraceEvent.PPid
	result["uid"] = ptraceEvent.Uid
	result["gid"] = ptraceEvent.Gid
	result["request"] = ptraceEvent.Request
	result["comm"] = ptraceEvent.Comm
	result["exe_path"] = ptraceEvent.ExePath

	// Add mount namespace ID
	result["mountnsid"] = ptraceEvent.MountNsID

	return result
}
