package ruleengine

import (
	"testing"

	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/utils/ptr"

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

	// Test with whitelisted address without dns cache.
	objCache := RuleObjectCacheMock{}
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test")
	if nn == nil {
		nn = &v1beta1.NetworkNeighborhood{}
		nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",

			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS:       "test.com",
					DNSNames:  []string{"test.com"},
					IPAddress: "1.1.1.1",
					Ports: []v1beta1.NetworkPort{
						{
							Port: ptr.To(int32(2023)),
						},
					},
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	failure := rule.ProcessEvent(utils.SSHEventType, sshEvent, &objCache)
	if failure != nil {
		t.Errorf("Expected nil since the SSH connection is to an allowed port, got %v", failure)
	}

	// Test disallowed port
	sshEvent.DstPort = 1234
	failure = rule.ProcessEvent(utils.SSHEventType, sshEvent, &objCache)
	if failure == nil {
		t.Errorf("Expected failure since the SSH connection is to a disallowed port, got nil")
	}

	// Test disallowed port that is in the egress list
	sshEvent.DstPort = 2023
	failure = rule.ProcessEvent(utils.SSHEventType, sshEvent, &objCache)
	if failure == nil {
		t.Errorf("Expected failure since the SSH connection is to a disallowed port, got nil")
	}

	// Test allowed port
	sshEvent.DstPort = 2022
	sshEvent.DstIP = "3.3.3.3"
	failure = rule.ProcessEvent(utils.SSHEventType, sshEvent, &objCache)
	if failure != nil {
		t.Errorf("Expected nil since the SSH connection is to an allowed port, got %v", failure)
	}
}
