package ruleengine

import (
	"testing"

	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/utils"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1003DisallowedSSHConnectionPort_ProcessEvent(t *testing.T) {
	rule := CreateRuleR1003MaliciousSSHConnection()

	sshEvent := &tracersshtype.Event{
		Event: eventtypes.Event{
			Timestamp: 2,
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
						PodName:       "test",
						Namespace:     "test",
					},
				},
				Runtime: eventtypes.BasicRuntimeMetadata{
					ContainerID:   "test",
					ContainerName: "test",
				},
			},
		},
		SrcIP:   "1.1.1.1",
		DstIP:   "2.2.2.2",
		DstPort: 22,
		SrcPort: 33333,
	}

	failure := rule.ProcessEvent(utils.SSHEventType, sshEvent, &RuleObjectCacheMock{})
	if failure != nil {
		t.Errorf("Expected nil since the SSH connection is to an allowed port, got %v", failure)
	}

	// Test disallowed port
	sshEvent.DstPort = 1234
	failure = rule.ProcessEvent(utils.SSHEventType, sshEvent, &RuleObjectCacheMock{})
	if failure == nil {
		t.Errorf("Expected failure since the SSH connection is to a disallowed port, got nil")
	}
}
