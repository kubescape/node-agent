package ruleengine

import (
	"testing"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"

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
			Args: []string{"test"},
		},
	}

	// Test with nil appProfileAccess
	ruleResult := rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objectcache.ObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil must have an appProfile")
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
	ruleResult = rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted")
	}

	// Test with non-whitelisted exec
	e = &events.ExecEvent{
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
			Comm: "/asdasd",
			Args: []string{"asdasd"},
		},
	}
	ruleResult = rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since exec is not whitelisted")
	}

	// Test /bin/sh
	profile.Spec.Containers[0].Execs = append(profile.Spec.Containers[0].Execs, v1beta1.ExecCalls{
		Path: "/bin/sh",
		Args: []string{"/bin/sh", "-s", "unix:cmd"},
	})
	objCache.SetApplicationProfile(profile)

	e.Comm = "sh"
	e.Args = []string{"/bin/sh", "-s", "unix:cmd"}
	ruleResult = rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted")
	}
}

func TestR0001UnexpectedProcessLaunchedArgCompare(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0001UnexpectedProcessLaunched()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	r.SetParameters(map[string]interface{}{"enforceArgs": false})

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{}
		profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
			Name: "test",
			Execs: []v1beta1.ExecCalls{
				{
					Path: "/test",
					Args: []string{"test"},
				},
			},
		})

		objCache.SetApplicationProfile(profile)
	}

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
			ExePath: "/test",
			Args:    []string{"/test", "something"},
		},
	}

	// Test with whitelisted exec
	ruleResult := rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted and args are not enforced")
	}

	// Create a new rule with enforceArgs set to true
	r = CreateRuleR0001UnexpectedProcessLaunched()
	r.SetParameters(map[string]interface{}{"enforceArgs": true})

	// Test with whitelisted exec and enforceArgs set to true
	ruleResult = rulemanager.ProcessRule(r, utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since exec is whitelisted but args are enforced")
	}

}
