package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

func TestR1004ExecFromMount(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1004ExecFromMount()
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
					Runtime: eventtypes.BasicRuntimeMetadata{ContainerID: "test"},
				},
			},
			Comm: "/test",
			Args: []string{},
		},
	}

	// Test case where path is not mounted
	ruleResult := ProcessRuleEvaluationTest(r, utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not from a mounted path")
	}

	// Test case where path is mounted, but not application profile is found
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
	ruleResult = ProcessRuleEvaluationTest(r, utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since no application profile is found")
	}

	// Test case where path is mounted, with application profile
	objCache.SetApplicationProfile(&v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  "test",
					Execs: []v1beta1.ExecCalls{{Path: "/var/other/test"}},
				},
			},
		},
	})
	ruleResult = ProcessRuleEvaluationTest(r, utils.ExecveEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is from a mounted path")
	}
}
