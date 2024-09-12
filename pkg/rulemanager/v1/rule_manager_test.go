package rulemanager

import (
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

func TestReportEvent(t *testing.T) {
	// Create a hardlink event
	e := &tracerhardlinktype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:    "test",
		OldPath: "test",
		NewPath: "test",
	}

	// Create a new rule
	reportEvent(utils.HardlinkEventType, e)
}

func reportEvent(eventType utils.EventType, event utils.K8sEvent) {
	k8sEvent := event.(*tracerhardlinktype.Event)
	if k8sEvent.GetNamespace() == "" || k8sEvent.GetPod() == "" {
		logger.L().Error("RuleManager - failed to get namespace and pod name from custom event")
		return
	}
}
