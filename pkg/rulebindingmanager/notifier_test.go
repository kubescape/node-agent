package rulebindingmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/kubescape/k8s-interface/k8sinterface"
)

type stubK8sClient struct {
	clientset kubernetes.Interface
}

func (s *stubK8sClient) GetWorkload(_, _, _ string) (k8sinterface.IWorkload, error) {
	return nil, nil
}

func (s *stubK8sClient) CalculateWorkloadParentRecursive(_ k8sinterface.IWorkload) (string, string, error) {
	return "", "", nil
}

func (s *stubK8sClient) GetKubernetesClient() kubernetes.Interface {
	return s.clientset
}

func (s *stubK8sClient) GetDynamicClient() dynamic.Interface {
	return nil
}

func TestNewRuleBindingNotifierImpl(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx-pod",
		},
	}

	notif := NewRuleBindingNotifierImpl(Added, pod)
	assert.Equal(t, Added, notif.GetAction())
	require.NotNil(t, notif.GetPod())
	assert.Equal(t, "nginx-pod", notif.GetPod().Name)
	assert.Equal(t, "default", notif.GetPod().Namespace)
}

func TestRuleBindingNotifierImplWithK8s(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kubescape",
			Name:      "node-agent",
		},
	}
	client := &stubK8sClient{
		clientset: k8sfake.NewClientset(pod),
	}

	notif, err := RuleBindingNotifierImplWithK8s(client, Removed, "kubescape", "node-agent")
	require.NoError(t, err)
	assert.Equal(t, Removed, notif.GetAction())
	assert.Equal(t, "node-agent", notif.GetPod().Name)
	assert.Equal(t, "kubescape", notif.GetPod().Namespace)

	_, err = RuleBindingNotifierImplWithK8s(client, Added, "kubescape", "nonexistent-pod")
	assert.Error(t, err)
}
