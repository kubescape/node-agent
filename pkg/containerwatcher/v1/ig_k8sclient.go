package containerwatcher

import (
	"strings"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

type IGK8sClient interface {
	GetNonRunningContainers(pod *corev1.Pod) []string
	GetRunningContainers(pod *corev1.Pod) []containercollection.Container
	ListContainers() (arr []containercollection.Container, err error)
}

var _ IGK8sClient = &IGK8sClientMock{}

type IGK8sClientMock struct {
}

func NewIGK8sClientMock() *IGK8sClientMock {
	return &IGK8sClientMock{}
}

// GetNonRunningContainers returns the list of containers IDs that are not running.
func (k *IGK8sClientMock) GetNonRunningContainers(pod *corev1.Pod) []string {
	ret := []string{}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID != "" && s.State.Running == nil {
			id := trimRuntimePrefix(s.ContainerID)
			if id == "" {
				continue
			}

			ret = append(ret, id)
		}
	}

	return ret
}

// GetRunningContainers returns a list of the containers of a given Pod that are running.
func (k *IGK8sClientMock) GetRunningContainers(pod *corev1.Pod) []containercollection.Container {
	containers := []containercollection.Container{}

	labels := map[string]string{}
	for k, v := range pod.ObjectMeta.Labels {
		labels[k] = v
	}

	containerStatuses := append([]v1.Container{}, pod.Spec.InitContainers...)
	containerStatuses = append(containerStatuses, pod.Spec.Containers...)

	for _, s := range containerStatuses {

		containers = append(containers, containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: s.Name,
				},
			},
		})
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *IGK8sClientMock) ListContainers() (arr []containercollection.Container, err error) {
	return []containercollection.Container{}, nil
}

// trimRuntimePrefix removes the runtime prefix from a container ID.
func trimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}
