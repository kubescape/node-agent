package adapters

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type KubeletTLSAdapter struct {
}

func NewKubeletTLSAdapter() *KubeletTLSAdapter {
	return &KubeletTLSAdapter{}
}

func (c *KubeletTLSAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	tlsEvent, ok := enrichedEvent.Event.(utils.KubeletTLSEvent)
	if !ok {
		return
	}

	pid := tlsEvent.GetPID()
	comm := tlsEvent.GetComm()
	tlsEventType := tlsEvent.GetTLSEventType()

	var direction string
	if tlsEventType == 0 {
		direction = "write"
	} else {
		direction = "read"
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["tls_data"] = tlsEvent.GetTLSData()
	baseRuntimeAlert.Arguments["tls_data_len"] = tlsEvent.GetTLSDataLen()
	baseRuntimeAlert.Arguments["tls_event_type"] = tlsEventType
	baseRuntimeAlert.Arguments["tls_direction"] = direction
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: fmt.Sprintf("%s (kubelet TLS %s)", comm, direction),
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			PID:  pid,
			Uid:  tlsEvent.GetUid(),
			Gid:  tlsEvent.GetGid(),
		},
		ContainerID: tlsEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(tlsEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   tlsEvent.GetPod(),
		PodLabels: tlsEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}
