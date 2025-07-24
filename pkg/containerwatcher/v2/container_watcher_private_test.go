package containerwatcher

import (
	"slices"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestAddRunningContainers(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container1",
				},
				{
					Name: "container2",
				},
			},
			InitContainers: []corev1.Container{
				{
					Name: "initContainer1",
				},
				{
					Name: "initContainer2",
				},
			},
		},
	}
	type ignore struct {
		namespace string
	}
	tests := []struct {
		notify                  *rulebindingmanager.RuleBindingNotify
		ignore                  ignore
		name                    string
		expectedRuleManagedPods []string
		preRuleManagedPods      []string
	}{
		{
			name: "Test add all containers",
			expectedRuleManagedPods: []string{
				"namespace1/pod1",
			},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Added,
				Pod:    pod,
			},
		},
		{
			name: "Test remove all containers",
			preRuleManagedPods: []string{
				"namespace1/pod1",
			},
			expectedRuleManagedPods: []string{},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Removed,
				Pod:    pod,
			},
		},
		{
			name: "Test add to existing managed pods",
			preRuleManagedPods: []string{
				"namespace1/pod1",
			},
			expectedRuleManagedPods: []string{
				"namespace1/pod1",
			},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Added,
				Pod:    pod,
			},
		},
		{
			name:                    "Test ignore pod",
			expectedRuleManagedPods: []string{},
			ignore: ignore{
				namespace: "namespace1",
			},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Added,
				Pod:    pod,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slices.Sort(tt.expectedRuleManagedPods)

			ncw := ContainerWatcher{
				cfg:                 config.Config{NamespaceName: tt.ignore.namespace},
				ruleManagedPods:     mapset.NewSet[string](tt.preRuleManagedPods...),
				containerCollection: &containercollection.ContainerCollection{},
				objectCache:         &objectcache.ObjectCacheMock{},
			}

			ncw.addRunningContainers(tt.notify)

			r := ncw.ruleManagedPods.ToSlice()
			slices.Sort(r)

			assert.Equal(t, tt.expectedRuleManagedPods, r)
		})
	}
}

func TestUnregisterContainer(t *testing.T) {
	tests := []struct {
		name                    string
		unregisterContainer     string
		unregisterContainersPod string
		preRuleManagedPods      []string
		podToContainers         map[string][]string
		expectedContainers      []string
	}{
		{
			name:                    "Test unregister container",
			unregisterContainer:     "container1",
			unregisterContainersPod: "pod1",
			podToContainers: map[string][]string{
				"pod1": {"container1"},
				"pod2": {"container2"},
			},
			preRuleManagedPods: []string{"test/pod2"},
			expectedContainers: []string{"container2"},
		},
		{
			name:                    "Test still in TimeBasedContainers",
			unregisterContainer:     "container1",
			unregisterContainersPod: "pod1",
			podToContainers: map[string][]string{
				"pod1": {"container1"},
				"pod2": {"container2"},
			},
			preRuleManagedPods: []string{"test/pod2"},
			expectedContainers: []string{"container2"},
		},
		{
			name:                    "Test still in RuleManagedPods",
			unregisterContainer:     "container1",
			unregisterContainersPod: "pod1",
			podToContainers: map[string][]string{
				"pod1": {"container1", "container2"},
			},
			preRuleManagedPods: []string{"test/pod1"},
			expectedContainers: []string{"container1", "container2"},
		},
		{
			name:                    "Test still in both",
			unregisterContainer:     "container1",
			unregisterContainersPod: "pod1",
			podToContainers: map[string][]string{
				"pod1": {"container1"},
				"pod2": {"container2"},
			},
			preRuleManagedPods: []string{"test/pod1", "test/pod2"},
			expectedContainers: []string{"container1", "container2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ncw := ContainerWatcher{
				ruleManagedPods:     mapset.NewSet[string](tt.preRuleManagedPods...),
				containerCollection: &containercollection.ContainerCollection{},
				objectCache:         &objectcache.ObjectCacheMock{},
			}

			for pod, containers := range tt.podToContainers {
				for _, s := range containers {
					ncw.containerCollection.AddContainer(&containercollection.Container{
						Runtime: containercollection.RuntimeMetadata{
							BasicRuntimeMetadata: types.BasicRuntimeMetadata{
								ContainerID: s,
							},
						},
						K8s: containercollection.K8sMetadata{
							BasicK8sMetadata: types.BasicK8sMetadata{
								PodName:   pod,
								Namespace: "test",
							},
						},
					})
				}
			}

			c := &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID: tt.unregisterContainer,
					},
				},
				K8s: containercollection.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodName:   tt.unregisterContainersPod,
						Namespace: "test",
					},
				},
			}

			ncw.unregisterContainer(c)

			var s []string
			for _, containerID := range ncw.containerCollection.GetContainersBySelector(&containercollection.ContainerSelector{}) {
				s = append(s, containerID.Runtime.ContainerID)
			}
			slices.Sort(s)
			slices.Sort(tt.expectedContainers)

			assert.Equal(t, tt.expectedContainers, s)
		})
	}
}
