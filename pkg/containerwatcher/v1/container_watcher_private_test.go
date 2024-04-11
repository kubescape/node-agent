package containerwatcher

import (
	"node-agent/pkg/rulebindingmanager"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
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
		name      string
		namespace string
	}
	tests := []struct {
		notify                        *rulebindingmanager.RuleBindingNotify
		ignore                        ignore
		name                          string
		expectedPreRunning            []string
		expectedRuleManagedContainers []string
		containersToRemove            []string
		containersToAdd               []string
		preTimeBasedContainers        []string
		preRuleManagedContainers      []string
	}{
		{
			name: "Test add all containers",
			expectedRuleManagedContainers: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			expectedPreRunning: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			containersToAdd: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Added,
				Pod:    pod,
			},
		},
		{
			name: "Test remove all containers",
			containersToRemove: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			preRuleManagedContainers: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			expectedRuleManagedContainers: []string{},
			expectedPreRunning:            []string{},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Removed,
				Pod:    pod,
			},
		},
		{
			name: "Test add some containers",
			expectedRuleManagedContainers: []string{
				"container1",
				"container2",
				"initContainer1",
				"initContainer2",
			},
			preRuleManagedContainers: []string{
				"container1",
			},
			preTimeBasedContainers: []string{
				"container1",
				"initContainer1",
			},
			expectedPreRunning: []string{
				"container2",
				"initContainer2",
			},
			containersToAdd: []string{
				"container2",
				"initContainer2",
			},
			notify: &rulebindingmanager.RuleBindingNotify{
				Action: rulebindingmanager.Added,
				Pod:    pod,
			},
		},
		{
			name:                          "Test ignore pod",
			expectedRuleManagedContainers: []string{},
			expectedPreRunning:            []string{},
			ignore: ignore{
				name:      "pod1",
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

			slices.Sort(tt.expectedRuleManagedContainers)
			slices.Sort(tt.expectedPreRunning)
			slices.Sort(tt.containersToRemove)

			ch := IGContainerWatcher{
				ruleManagedContainers:   mapset.NewSet[string](tt.preRuleManagedContainers...),
				timeBasedContainers:     mapset.NewSet[string](tt.preTimeBasedContainers...),
				preRunningContainersIDs: mapset.NewSet[string](),
				containerCollection:     &containercollection.ContainerCollection{},
				tracerCollection:        &tracercollection.TracerCollection{},
				namespace:               tt.ignore.namespace,
				podName:                 tt.ignore.name,
			}

			// Mock the calls to the Kubernetes client here
			k8sMock := NewIGK8sClientMock()

			ch.addRunningContainers(k8sMock, tt.notify)

			r := ch.ruleManagedContainers.ToSlice()
			p := ch.preRunningContainersIDs.ToSlice()
			slices.Sort(r)
			slices.Sort(p)

			assert.Equal(t, tt.expectedRuleManagedContainers, r)
			assert.Equal(t, tt.expectedPreRunning, p)

			for _, containerID := range tt.containersToRemove {
				assert.False(t, ch.ruleManagedContainers.Contains(containerID))
			}

			for _, containerID := range tt.containersToAdd {
				assert.NotNil(t, ch.containerCollection.GetContainer(containerID))
			}
		})
	}
}

func TestUnregisterContainer(t *testing.T) {

	tests := []struct {
		name                     string
		unregisterContainer      string
		preTimeBasedContainers   []string
		preRuleManagedContainers []string
		containers               []string
		expectedContainers       []string
	}{
		{
			name:                     "Test unregister container",
			unregisterContainer:      "container1",
			containers:               []string{"container1", "container2"},
			preTimeBasedContainers:   []string{"container2"},
			preRuleManagedContainers: []string{"container2"},
			expectedContainers:       []string{"container2"},
		},
		{
			name:                     "Test still in TimeBasedContainers",
			unregisterContainer:      "container1",
			containers:               []string{"container1", "container2"},
			preTimeBasedContainers:   []string{"container1", "container2"},
			preRuleManagedContainers: []string{"container2"},
			expectedContainers:       []string{"container1", "container2"},
		},
		{
			name:                     "Test still in RuleManagedContainers",
			unregisterContainer:      "container1",
			containers:               []string{"container1", "container2"},
			preTimeBasedContainers:   []string{"container2"},
			preRuleManagedContainers: []string{"container1", "container2"},
			expectedContainers:       []string{"container1", "container2"},
		},
		{
			name:                     "Test still in both",
			unregisterContainer:      "container1",
			containers:               []string{"container1", "container2"},
			preTimeBasedContainers:   []string{"container1", "container2"},
			preRuleManagedContainers: []string{"container1", "container2"},
			expectedContainers:       []string{"container1", "container2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ch := IGContainerWatcher{
				ruleManagedContainers:   mapset.NewSet[string](tt.preRuleManagedContainers...),
				timeBasedContainers:     mapset.NewSet[string](tt.preTimeBasedContainers...),
				preRunningContainersIDs: mapset.NewSet[string](),
				containerCollection:     &containercollection.ContainerCollection{},
				tracerCollection:        &tracercollection.TracerCollection{},
			}

			for _, s := range tt.containers {
				ch.containerCollection.AddContainer(&containercollection.Container{
					Runtime: containercollection.RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							ContainerID: s,
						},
					},
				})
			}

			c := &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID: tt.unregisterContainer,
					},
				},
			}

			ch.unregisterContainer(c)

			var s []string
			for _, containerID := range ch.containerCollection.GetContainersBySelector(&containercollection.ContainerSelector{}) {
				s = append(s, containerID.Runtime.ContainerID)
			}
			slices.Sort(s)
			slices.Sort(tt.expectedContainers)

			assert.Equal(t, tt.expectedContainers, s)
		})
	}
}
