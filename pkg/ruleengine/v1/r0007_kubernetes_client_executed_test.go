package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR0007KubernetesClientExecuted(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0007KubernetesClientExecuted()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create an exec event
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
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
			Args: []string{},
		},
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Execs: []v1beta1.ExecCalls{
				{
					Path: "asdf",
					Args: []string{"test"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

	ruleResult := ruleprocess.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not a k8s client")
		return
	}

	e.Comm = "kubectl"

	ruleResult = ruleprocess.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is a k8s client")
		return
	}
}
