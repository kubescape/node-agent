package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR0010UnexpectedSensitiveFileAccess(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0010UnexpectedSensitiveFileAccess()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

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

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(utils.OpenEventType, e, &objectcache.ObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
	}

	// Test with whitelisted file
	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						Opens: []v1beta1.OpenCalls{
							{
								Path:  "/test",
								Flags: []string{"O_RDONLY"},
							},
						},
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted and not sensitive")
	}

	// Test with non whitelisted file, but not sensitive
	e.FullPath = "/var/test1"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is not whitelisted and not sensitive")
	}

	// Test with sensitive file that is whitelisted
	e.FullPath = "/etc/shadow"
	profile.Spec.Containers[0].Opens[0].Path = "/etc/shadow"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted and sensitive")
	}

	// Test with sensitive file, but not whitelisted
	e.FullPath = "/etc/shadow"
	profile.Spec.Containers[0].Opens[0].Path = "/test"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file is not whitelisted and sensitive")
	}

	// Test with sensitive file that originates from additionalPaths parameter
	e.FullPath = "/etc/blabla"
	profile.Spec.Containers[0].Opens[0].Path = "/test"
	additionalPaths := []interface{}{"/etc/blabla"}
	r.SetParameters(map[string]interface{}{"additionalPaths": additionalPaths})
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file is not whitelisted and sensitive")
	}

	e.FullPath = "/tmp/blabla"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted and not sensitive")
	}

	profile = &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "test",
					Opens: []v1beta1.OpenCalls{
						{
							Path:  "/etc/\u22ef",
							Flags: []string{"O_RDONLY"},
						},
					},
				},
			},
		},
	}
	objCache.SetApplicationProfile(profile)

	e.FullPath = "/etc/blabla"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted and not sensitive")
	}

}
