package dynamicwatcher

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type namespacePodRecorder struct {
	watcher.AdaptorMock
	pods []*corev1.Pod
}

func (r *namespacePodRecorder) AddHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		r.pods = append(r.pods, pod)
	}
}

func TestNamespaceFilterSeedsExcludedPodMetadata(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		require.Equal(t, "spec.nodeName=node-one", action.(ktesting.ListAction).GetListRestrictions().Fields.String())
		return true, &corev1.PodList{ResourceVersion: "123", Items: []corev1.Pod{{Name: "pay", Namespace: "payments"}}}, nil
	})
	wh := NewWatchHandler(&k8sinterface.KubernetesApi{KubernetesClient: client}, nil, func(string) bool { return true })
	recorder := &namespacePodRecorder{}
	wh.AddAdaptor(recorder)
	wh.EnableDynamicNamespaceFiltering()
	require.False(t, wh.skipNamespaceFunc("payments"), "metadata must outlive exclusion")
	version, err := wh.seedPods(t.Context(), metav1.ListOptions{FieldSelector: "spec.nodeName=node-one"})
	require.NoError(t, err)
	require.Equal(t, "123", version)
	require.Len(t, recorder.pods, 1)
	require.Equal(t, "payments", recorder.pods[0].Namespace)
}
