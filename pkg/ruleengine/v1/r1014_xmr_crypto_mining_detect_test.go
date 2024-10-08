package ruleengine

import (
	"fmt"
	"testing"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// TestR1014CryptoMinerCombinedEvent tests that R1014CryptoMinerDetected triggers an alert
// only when all three events (Open, DNS, RandomX) occur in sequence
func TestR1014CryptoMinerCombinedEvent(t *testing.T) {
	// Reset flags to ensure clean state
	randomx_event = false
	dns_event = false
	open_event = false
	alertTriggered = false

	// Create a new rule
	r := CreateRuleR1014CryptoMinerDetected()
	if r == nil {
		t.Fatalf("Expected R1014CryptoMinerDetected rule instance, but got nil")
	}

	// Create a RandomX event
	// Test RandomX event
	e3 := &tracerrandomxtype.Event{
		Comm: "test",
	}

	// Create a DNS event for a known crypto mining domain
	// Create dns event
	e2 := &tracerdnstype.Event{
		DNSName: "xmr.gntl.uk.",
	}

	// Create an OpenEvent for a crypto miner file path
	// Create a file access event
	e := &traceropentype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Path:     "/test",
		FullPath: "/test",
		Flags:    []string{"O_RDONLY"},
	}

	e.FullPath = "/proc/meminfo/asdasd"
	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Opens: []v1beta1.OpenCalls{
				{
					Path:  "/proc/meminfo",
					Flags: []string{"O_RDONLY"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	// Process the RandomX event
	ruleResult := r.ProcessEvent(utils.RandomXEventType, e3, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected nil ruleResult since one event is insufficient to trigger an alert")
	}

	// Process the DNS event
	ruleResult = r.ProcessEvent(utils.DnsEventType, e2, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected nil ruleResult since two events are insufficient to trigger an alert")
		return
	}

	// Process the OpenEvent
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be non-nil, indicating an alert was triggered after all events")
	}

	// Verify alert is triggered only once
	if !alertTriggered {
		t.Errorf("Expected alertTriggered to be true")
	}

	// Process another OpenEvent to check that no duplicate alert is issued
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected nil ruleResult since alert should be triggered only once")
	}

	fmt.Println("TestR1014CryptoMinerCombinedEvent passed successfully.")
}
