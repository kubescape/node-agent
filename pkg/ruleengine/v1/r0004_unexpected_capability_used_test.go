package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0004UnexpectedCapabilityUsed(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0004UnexpectedCapabilityUsed()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	e := &tracercapabilitiestype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		CapName: "test_cap",
		Syscall: "test_call",
	}

	// Test with nil appProfileAccess
	ruleResult := ProcessRuleEvaluationTest(r, utils.CapabilitiesEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since no appProfile is present")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name:         "test",
			Capabilities: []string{"test_cap"},
		})

		objCache.SetApplicationProfile(profile)
	}

	// Test with mock appProfile
	ruleResult = ProcessRuleEvaluationTest(r, utils.CapabilitiesEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since capability is in the profile")
	}
}
