package ruleengine

import (
	"testing"

	"node-agent/pkg/objectcache"
	"node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR0001UnexpectedProcessLaunched(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0001UnexpectedProcessLaunched()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	e := &tracerexectype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm: "/test",
		Args: []string{"test"},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &objectcache.ObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil must have an appProfile")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Execs: []v1beta1.ExecCalls{
				{
					Path: "test",
					Args: []string{"test"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	// Test with whitelisted exec
	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted")
	}

	// Test with non-whitelisted exec
	e = &tracerexectype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm: "/asdasd",
		Args: []string{"asdasd"},
	}
	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since exec is not whitelisted")
	}
}
