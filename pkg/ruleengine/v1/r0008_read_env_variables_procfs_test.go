package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR0008ReadingEnvVariablesFromProcFS(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0008ReadEnvironmentVariablesProcFS()
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
	ruleResult := r.ProcessEvent(utils.OpenEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
		return
	}

	// Test with whitelisted file
	e.FullPath = "/proc/1/environ"
	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Opens: []v1beta1.OpenCalls{
				{
					Path:  "/proc/" + dynamicpathdetector.DynamicIdentifier + "/environ",
					Flags: []string{"O_RDONLY"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted")
	}

	// Test with non-whitelisted file
	e.FullPath = "/proc/2/environ"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil since there is a read from /environ")
	}

	// Test with non /proc file
	e.FullPath = "/test"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is not /proc file")
	}
}
