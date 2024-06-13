package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

func TestR1011LdPreloadHook(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1011LdPreloadHook()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
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
	ruleResult := r.ProcessEvent(utils.OpenEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since ld_preload file is opened with write flag")
	}

	// Test with ld.so.preload file opened with read flag
	e.FlagsRaw = 0
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since ld_preload file is opened with read flag")
	}

	// Test with pod spec
	objCache := RuleObjectCacheMock{}
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
}
