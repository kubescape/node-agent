package ruleengine

import (
	"fmt"
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
)

func TestR1010SymlinkCreatedOverSensitiveFile(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1010SymlinkCreatedOverSensitiveFile() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						PolicyByRuleId: map[string]v1beta1.RulePolicy{
							R1010ID: {
								AllowedProcesses: []string{"/usr/sbin/groupadd"},
							},
						},
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

	// Create a symlink event
	e := &tracersymlinktype.Event{
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

	ruleResult := ProcessRuleEvaluationTest(r, utils.SymlinkEventType, e, &objCache)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since symlink path is not sensitive")
		return
	}

	// Create a symlink event with sensitive file path
	e.OldPath = "/etc/shadow"
	e.NewPath = "/etc/abc"

	ruleResult = ProcessRuleEvaluationTest(r, utils.SymlinkEventType, e, &objCache)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of symlink is used over sensitive file")
		return
	}

	e.OldPath = "/etc/abc"
	ruleResult = ProcessRuleEvaluationTest(r, utils.SymlinkEventType, e, &objCache)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since symlink is not used over sensitive file")
		return
	}

	// Test with whitelisted process
	e.Comm = "/usr/sbin/groupadd"
	e.OldPath = "/etc/shadow"
	e.NewPath = "/etc/abc"

	ruleResult = ProcessRuleEvaluationTest(r, utils.SymlinkEventType, e, &objCache)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since file is whitelisted and not sensitive")
		return
	}
}
