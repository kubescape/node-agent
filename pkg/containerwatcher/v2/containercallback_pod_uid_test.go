package containerwatcher

import (
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestSharedContainerDataPodUID(t *testing.T) {
	for _, tc := range []struct {
		name, expectedUID, fetchedUID, mirrorUID, wantError string
	}{
		{"same Pod", "original", "original", "", ""},
		{"same name replacement", "original", "replacement", "", "pod UID changed"},
		{"container UID not enriched yet", "", "fetched", "", ""},
		{"missing fetched UID", "original", "", "", "fetched pod has no UID"},
		{"static Pod mirror", "static-uid", "api-mirror-uid", "static-uid", ""},
		{"stale static Pod mirror", "static-uid", "api-mirror-uid", "replacement-static-uid", "pod UID changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
				ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "same-name", UID: types.UID(tc.fetchedUID)},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:1"}}},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "containerd://original-container"}}},
			}
			if tc.mirrorUID != "" {
				pod.Annotations = map[string]string{"kubernetes.io/config.mirror": tc.mirrorUID}
			}
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			cw := &ContainerWatcher{clusterName: "test", k8sClient: &k8sinterface.KubernetesApi{
				Context: t.Context(), DynamicClient: dynamicfake.NewSimpleDynamicClient(scheme, pod),
			}}
			container := &containercollection.Container{}
			container.Runtime.ContainerID = "original-container"
			container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName = "test", "same-name", "app"
			container.K8s.PodUID = tc.expectedUID
			data, err := cw.getSharedWatchedContainerData(container)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.Nil(t, data, "replacement metadata must never be published")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.fetchedUID, data.PodUID)
			require.Equal(t, "original-container", data.ContainerID)
			require.NotEmpty(t, data.Wlid)
		})
	}
}

func TestSharedContainerDataMissingRuntimeUIDRequiresOwnership(t *testing.T) {
	for _, group := range []string{"regular", "init", "ephemeral", "replacement", "empty"} {
		t.Run(group, func(t *testing.T) {
			status := corev1.ContainerStatus{Name: "app", ContainerID: "containerd://original-container"}
			pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "same-name", UID: "fetched"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:1"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
			switch group {
			case "regular":
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{status}
			case "init":
				pod.Status.InitContainerStatuses = []corev1.ContainerStatus{status}
			case "ephemeral":
				pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{status}
			case "replacement":
				status.ContainerID = "containerd://replacement-container"
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{status}
			}
			scheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(scheme))
			cw := &ContainerWatcher{clusterName: "test", k8sClient: &k8sinterface.KubernetesApi{Context: t.Context(), DynamicClient: dynamicfake.NewSimpleDynamicClient(scheme, pod)}}
			container := &containercollection.Container{}
			container.Runtime.ContainerID = "original-container"
			container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName = "test", "same-name", "app"
			data, err := cw.getSharedWatchedContainerData(container)
			if group == "replacement" || group == "empty" {
				require.ErrorContains(t, err, "does not own container")
				require.Nil(t, data)
			} else {
				require.NoError(t, err)
				require.Equal(t, "fetched", data.PodUID)
			}
		})
	}
}
