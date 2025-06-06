package ruleengine

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
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
	e := &events.OpenEvent{
		Event: traceropentype.Event{
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
		},
	}
	// Test with nil appProfileAccess
	ruleResult := ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objectcache.ObjectCacheMock{})
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
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted")
	}

	e.FullPath = "/var/log/app123.log"
	profile = &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "test",
					Opens: []v1beta1.OpenCalls{
						{
							Path:  "/var/log/\u22ef",
							Flags: []string{"O_RDONLY"},
						},
					},
				},
			},
		},
	}
	objCache.SetApplicationProfile(profile)
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": []interface{}{}})
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file matches dynamic path in profile")
	}

	// Test with dynamic path but different flags
	e.Flags = []string{"O_WRONLY"}
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since flag is not whitelisted for dynamic path")
	}

	// Test with dynamic path but non-matching file
	e.FullPath = "/var/log/different_directory/app123.log"
	e.Flags = []string{"O_RDONLY"}
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file does not match dynamic path structure")
	}

	// Test with multiple dynamic segments
	e.FullPath = "/var/log/user123/app456.log"
	profile.Spec.Containers[0].Opens = []v1beta1.OpenCalls{
		{
			Path:  "/var/log/\u22ef/\u22ef",
			Flags: []string{"O_RDONLY"},
		},
	}
	objCache.SetApplicationProfile(profile)
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file matches multiple dynamic segments in profile")
	}

	// Test with whitelisted file, but different flags
	e.Flags = []string{"O_WRONLY"}
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
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
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)

	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is mounted")
	}

	// Test with ignored prefix
	e.FullPath = "/var/test1"
	ignorePrefixes := []interface{}{"/var"}
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": ignorePrefixes})
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is ignored")
	}

	// Test with include prefixes
	e.FullPath = "/var/test1"
	includePrefixes := []interface{}{"/etc"}
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": ignorePrefixes, "includePrefixes": includePrefixes})
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is not included")
	}

	// Test the case where the path is included
	e.FullPath = "/etc/passwd"
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file is included")
	}

	// Test the case where the path is included but ignored
	e.FullPath = "/etc/some/random/path/passwd"
	ignorePrefixes = []interface{}{"/etc/some"}
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": ignorePrefixes, "includePrefixes": includePrefixes})
	ruleResult = ruleprocess.ProcessRule(r, utils.OpenEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is ignored")
	}
}
