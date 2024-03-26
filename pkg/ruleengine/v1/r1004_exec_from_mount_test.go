package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

func TestR1004ExecFromMount(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1004ExecFromMount()
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
		Args: []string{},
	}

	// Test case where path is not mounted
	ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not from a mounted path")
	}

	// Test case where path is mounted

	e.Comm = "/var/test1/test"
	objCache := RuleObjectCacheMock{}
	objCache.SetPodSpec(
		&corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "test",
							MountPath: "/var/test1",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "test",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/test1",
						},
					},
				},
			},
		},
	)

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is from a mounted path")
	}
}
