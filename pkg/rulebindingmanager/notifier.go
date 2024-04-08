package rulebindingmanager

import (
	"context"
	"github.com/kubescape/node-agent/pkg/k8sclient"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

type Actions int

const (
	Added   Actions = 0
	Removed Actions = 1
)

type RuleBindingNotify struct {
	Pod    corev1.Pod
	Action Actions
}

func NewRuleBindingNotifierImpl(action Actions, pod corev1.Pod) RuleBindingNotify {
	return RuleBindingNotify{
		Pod:    pod,
		Action: action,
	}
}
func RuleBindingNotifierImplWithK8s(k8sClient k8sclient.K8sClientInterface, action Actions, namespace, name string) (RuleBindingNotify, error) {
	pod, err := k8sClient.GetKubernetesClient().CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return RuleBindingNotify{}, err
	}
	return RuleBindingNotify{
		Pod:    *pod,
		Action: action,
	}, nil
}

func (r *RuleBindingNotify) GetPod() *corev1.Pod {
	return &r.Pod
}
func (r *RuleBindingNotify) GetAction() Actions {
	return r.Action
}
