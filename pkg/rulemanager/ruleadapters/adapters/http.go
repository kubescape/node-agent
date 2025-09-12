package adapters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type HTTPAdapter struct {
}

func NewHTTPAdapter() *HTTPAdapter {
	return &HTTPAdapter{}
}

func (c *HTTPAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent) {
	//httpEvent, ok := enrichedEvent.Event.(*tracerhttptype.Event)
	//if !ok {
	//	return
	//}

	//baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	//baseRuntimeAlert.InfectedPID = httpEvent.Pid
	//baseRuntimeAlert.Arguments = map[string]interface{}{
	//	"other_ip":   httpEvent.OtherIp,
	//	"other_port": httpEvent.OtherPort,
	//	"internal":   httpEvent.Internal,
	//	"direction":  httpEvent.Direction,
	//}
	//baseRuntimeAlert.Identifiers = &common.Identifiers{
	//	Network: &common.NetworkEntity{
	//		DstIP:    httpEvent.OtherIp,
	//		DstPort:  int(httpEvent.OtherPort),
	//		Protocol: "http",
	//	},
	//	Http: &common.HttpEntity{
	//		Method:    httpEvent.Request.Method,
	//		Domain:    httpEvent.Request.Host,
	//		UserAgent: httpEvent.Request.UserAgent(),
	//		Endpoint:  httpEvent.Request.URL.Path,
	//	},
	//}
	//failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	//runtimeProcessDetails := apitypes.ProcessTree{
	//	ProcessTree: apitypes.Process{
	//		PID: httpEvent.Pid,
	//		Uid: &httpEvent.Uid,
	//		Gid: &httpEvent.Gid,
	//	},
	//	ContainerID: httpEvent.Runtime.ContainerID,
	//}
	//failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	//failure.SetTriggerEvent(httpEvent.Event)

	//runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
	//	PodName:   httpEvent.GetPod(),
	//	PodLabels: httpEvent.K8s.PodLabels,
	//}
	//failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
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
