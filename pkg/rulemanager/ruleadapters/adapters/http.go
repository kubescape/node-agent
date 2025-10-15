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

func (c *HTTPAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	httpEvent, ok := enrichedEvent.Event.(utils.HttpEvent)
	if !ok || enrichedEvent.EventType != utils.HTTPEventType {
		return
	}

	request := httpEvent.GetRequest()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = httpEvent.GetPID()
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"internal":  httpEvent.GetInternal(),
		"direction": httpEvent.GetDirection(),
	}
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

func (c *HTTPAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	//httpEvent, ok := enrichedEvent.Event.(*tracerhttptype.Event)
	//if !ok {
	//	return nil
	//}

	//result := ConvertToMap(&httpEvent.Event)

	//result["pid"] = httpEvent.Pid
	//result["uid"] = httpEvent.Uid
	//result["gid"] = httpEvent.Gid
	//result["other_port"] = httpEvent.OtherPort
	//result["other_ip"] = httpEvent.OtherIp
	//result["internal"] = httpEvent.Internal
	//result["direction"] = httpEvent.Direction

	//if httpEvent.Request != nil {
	//	result["request"] = httpEvent.Request
	//}
	//if httpEvent.Response != nil {
	//	result["response"] = httpEvent.Response
	//}

	//result["mountnsid"] = httpEvent.MountNsID

	return map[string]interface{}{}
}
