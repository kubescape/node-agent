package adapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type HTTPAdapter struct {
}

func NewHTTPAdapter() *HTTPAdapter {
	return &HTTPAdapter{}
}

func (c *HTTPAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	httpEvent, ok := enrichedEvent.Event.(*tracerhttptype.Event)
	if !ok {
		return
	}

	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = httpEvent.Pid
	baseRuntimeAlert.Arguments = map[string]interface{}{
		"other_ip":   httpEvent.OtherIp,
		"other_port": httpEvent.OtherPort,
		"internal":   httpEvent.Internal,
		"direction":  httpEvent.Direction,
	}
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: "http_process", // HTTP events don't have Comm field
		},
		Network: &common.NetworkEntity{
			DstIP:    httpEvent.OtherIp,
			DstPort:  int(httpEvent.OtherPort),
			Protocol: "http",
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID: httpEvent.Pid,
			Uid: &httpEvent.Uid,
			Gid: &httpEvent.Gid,
		},
		ContainerID: httpEvent.Runtime.ContainerID,
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(httpEvent.Event)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   httpEvent.GetPod(),
		PodLabels: httpEvent.K8s.PodLabels,
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

func (c *HTTPAdapter) ToMap(enrichedEvent *events.EnrichedEvent) map[string]interface{} {
	httpEvent, ok := enrichedEvent.Event.(*tracerhttptype.Event)
	if !ok {
		return nil
	}

	// Start with the base event using ConvertToMap
	result := ConvertToMap(&httpEvent.Event)

	// Add HTTP-specific fields using JSON tags as keys
	result["pid"] = httpEvent.Pid
	result["uid"] = httpEvent.Uid
	result["gid"] = httpEvent.Gid
	result["other_port"] = httpEvent.OtherPort
	result["other_ip"] = httpEvent.OtherIp
	result["internal"] = httpEvent.Internal
	result["direction"] = httpEvent.Direction

	// Add HTTP request/response data if available
	if httpEvent.Request != nil {
		result["request"] = httpEvent.Request
	}
	if httpEvent.Response != nil {
		result["response"] = httpEvent.Response
	}

	// Add mount namespace ID
	result["mountnsid"] = httpEvent.MountNsID

	return result
}
