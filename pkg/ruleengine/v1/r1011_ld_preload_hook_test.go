package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

func TestR1011LdPreloadHook(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1011LdPreloadHook() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nilllll")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}

	// Create open event
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
		Comm:     "test",
		FullPath: "/etc/ld.so.preload",
		FlagsRaw: 1,
	}

	// Test with existing ld_preload file
	ruleResult := r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since ld_preload file is opened with write flag")
	}

	// Test with ld.so.preload file opened with read flag
	e.FlagsRaw = 0
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since ld_preload file is opened with read flag")
	}

	// Test with pod spec
	objCache.SetPodSpec(&corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "test",
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "test",
						MountPath: "/var",
					},
				},
				Env: []corev1.EnvVar{
					{
						Name:  "LD_PRELOAD",
						Value: "/var/test.so",
					},
				},
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "test",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var",
					},
				},
			},
		},
	})
	e.FullPath = "/var/test.so"
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since LD_PRELOAD is set in pod spec")
	}

	// Create open event
	e2 := &tracerexectype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm: "java",
	}
	// Test with exec event
	ruleResult = r.ProcessEvent(utils.ExecveEventType, e2, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec event is on java")
	}

	e3 := &traceropentype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:     "test",
		FullPath: "/etc/ld.so.preload",
		FlagsRaw: 1,
	}

	objCache = RuleObjectCacheMock{}
	profile = objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						PolicyByRuleId: map[string]v1beta1.RulePolicy{
							R1011ID: {
								AllowedProcesses: []string{"test"},
							},
						},
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}
	// Test with exec event
	ruleResult = r.ProcessEvent(utils.OpenEventType, e3, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec event is on java")
	}

}
