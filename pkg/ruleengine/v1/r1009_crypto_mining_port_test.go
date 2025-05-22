package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1009CryptoMiningRelatedPort(t *testing.T) {
	rule := &R1009CryptoMiningRelatedPort{}

	// Test when eventType is not NetworkEventType
	eventType := utils.RandomXEventType
	event := &tracernetworktype.Event{}
	result := ruleprocess.ProcessRule(rule, eventType, event, &RuleObjectCacheMock{})
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}

	// Test when event is not of type *tracernetworktype.Event
	eventType = utils.NetworkEventType
	event2 := &tracerexectype.Event{}
	result = ruleprocess.ProcessRule(rule, eventType, event2, &RuleObjectCacheMock{})
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}

	var port int32 = 3334

	// Test with whitelisted port
	objCache := RuleObjectCacheMock{}
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test")
	if nn == nil {
		nn = &v1beta1.NetworkNeighborhood{}
		nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",

			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS: "test.com",
					Ports: []v1beta1.NetworkPort{
						{
							Port: &port,
						},
					},
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	// Test when event meets all conditions to return a ruleFailure
	eventType = utils.NetworkEventType
	event = &tracernetworktype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Proto:   "TCP",
		PktType: "OUTGOING",
		Port:    CommonlyUsedCryptoMinersPorts[0],
		Comm:    "testComm",
		Gid:     1,
		Pid:     1,
		Uid:     1,
	}
	result = ruleprocess.ProcessRule(rule, eventType, event, &objCache)
	if result == nil {
		t.Errorf("Expected ruleFailure, got nil")
	}

	// Test when event does not meet conditions to return a ruleFailure
	port = 3333
	objCache.nn.Spec.Containers[0].Egress[0].Ports[0].Port = &port
	result = ruleprocess.ProcessRule(rule, eventType, event, &objCache)
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}
}
