package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type HTTPAdapter struct {
}

func NewHTTPAdapter() *HTTPAdapter {
	return &HTTPAdapter{}
}

func (c *HTTPAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	httpEvent, ok := enrichedEvent.Event.(utils.HttpEvent)
	if !ok {
		return
	}

	request := httpEvent.GetRequest()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = httpEvent.GetPID()
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["internal"] = httpEvent.GetInternal()
	baseRuntimeAlert.Arguments["direction"] = httpEvent.GetDirection()
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Network: &common.NetworkEntity{
			Protocol: "http",
		},
		Http: &common.HttpEntity{
			Method:    request.Method,
			Domain:    request.Host,
			UserAgent: request.UserAgent(),
			Endpoint:  request.URL.Path,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID: httpEvent.GetPID(),
			Uid: httpEvent.GetUid(),
			Gid: httpEvent.GetGid(),
		},
		ContainerID: httpEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(httpEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   httpEvent.GetPod(),
		PodLabels: httpEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *HTTPAdapter) ToMap(enrichedEvent *events.EnrichedEvent) any {
	httpEvent, ok := enrichedEvent.Event.(utils.HttpEvent)
	if !ok {
		return nil
	}

	return ConvertToMap(httpEvent)
}
