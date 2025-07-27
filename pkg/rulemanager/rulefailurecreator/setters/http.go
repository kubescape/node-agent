package setters

import (
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

type HTTPFailureSetter struct {
}

func NewHTTPCreator() *HTTPFailureSetter {
	return &HTTPFailureSetter{}
}

func (c *HTTPFailureSetter) SetFailureMetadata(failure ruleengine.RuleFailure, enrichedEvent *events.EnrichedEvent) {
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
