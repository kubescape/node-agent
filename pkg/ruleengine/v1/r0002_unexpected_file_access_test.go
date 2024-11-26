package ruleengine

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR0002UnexpectedFileAccess(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0002UnexpectedFileAccess()
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
		t.Errorf("Expected ruleResult to be nil since file is whitelisted")
	}

	// Test with whitelisted file, but different flags
	e.Flags = []string{"O_WRONLY"}
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since flag is not whitelisted")
	}

	// Test with mounted file
	e.Flags = []string{"O_RDONLY"}
	e.FullPath = "/var/test1"
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
	r.SetParameters(map[string]interface{}{"ignoreMounts": true})
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)

	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is mounted")
	}

	// Test with ignored prefix
	e.FullPath = "/var/test1"
	ignorePrefixes := []interface{}{"/var"}
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": ignorePrefixes})
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is ignored")
	}
}
