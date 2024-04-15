package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1003DisallowedSSHConnectionPort_ProcessEvent(t *testing.T) {
	rule := CreateRuleR1003MaliciousSSHConnection()

	// Test case 1: SSH connection to disallowed port
	networkEvent := &tracernetworktype.Event{
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
		PktType: "OUTGOING",
		Proto:   "TCP",
		Port:    2222,
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1",
		},
		Pid: 1,
	}

	openEvent := &traceropentype.Event{
		Event: eventtypes.Event{
			Timestamp: 1,
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
		FullPath: "/etc/ssh/sshd_config",
		Pid:      1,
	}
	rule.ProcessEvent(utils.OpenEventType, openEvent, &RuleObjectCacheMock{})
	failure := rule.ProcessEvent(utils.NetworkEventType, networkEvent, &RuleObjectCacheMock{})
	if failure == nil {
		t.Errorf("Expected failure, but got nil")
	}

	// Test case 2: SSH connection to allowed port
	networkEvent.Port = 22
	failure = rule.ProcessEvent(utils.NetworkEventType, networkEvent, &RuleObjectCacheMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 3: SSH connection to disallowed port, but not from SSH initiator
	networkEvent.Port = 2222
	networkEvent.Pid = 2
	failure = rule.ProcessEvent(utils.NetworkEventType, networkEvent, &RuleObjectCacheMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 4: SSH connection to disallowed port, but not from SSH initiator
	networkEvent.Port = 2222
	networkEvent.Pid = 1
	networkEvent.Timestamp = 3
	failure = rule.ProcessEvent(utils.NetworkEventType, networkEvent, &RuleObjectCacheMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 5: Time diff is greater than MaxTimeDiffInSeconds
	networkEvent.Port = 2222
	networkEvent.Pid = 1
	networkEvent.Timestamp = 5
	failure = rule.ProcessEvent(utils.NetworkEventType, networkEvent, &RuleObjectCacheMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}
}
