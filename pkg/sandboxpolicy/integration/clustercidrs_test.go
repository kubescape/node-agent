package integration

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestClusterCIDRsSources(t *testing.T) {
	ctx := context.Background()
	kubeadm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "kubeadm-config", Namespace: "kube-system"},
		Data: map[string]string{"ClusterConfiguration": "networking:\n  podSubnet: 10.244.0.0/16,fd00:10:244::/56\n  serviceSubnet: 10.96.0.0/16\n"}}
	node := func(name string, cidrs ...string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.NodeSpec{PodCIDRs: cidrs}}
	}

	// Nodes and ServiceCIDR objects come first.
	got := ClusterCIDRs(ctx, fake.NewSimpleClientset(node("a", "10.244.1.0/24"), node("b", "10.244.2.0/24"), kubeadm,
		&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.96.0.0/12"}}}))
	if !reflect.DeepEqual(got.Pods, []string{"10.244.1.0/24", "10.244.2.0/24"}) || !reflect.DeepEqual(got.Services, []string{"10.96.0.0/12"}) || len(got.Missing) != 0 {
		t.Fatalf("primary sources %+v", got)
	}
	// Without them, kubeadm-config.
	got = ClusterCIDRs(ctx, fake.NewSimpleClientset(node("a"), kubeadm))
	if !reflect.DeepEqual(got.Pods, []string{"10.244.0.0/16", "fd00:10:244::/56"}) || !reflect.DeepEqual(got.Services, []string{"10.96.0.0/16"}) {
		t.Fatalf("kubeadm fallback %+v", got)
	}
	// A VPC-routed CNI on a managed cluster: nothing for pods.
	got = ClusterCIDRs(ctx, fake.NewSimpleClientset(node("a"),
		&networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"172.20.0.0/16"}}}))
	if len(got.Pods) != 0 || !reflect.DeepEqual(got.Missing, []string{"pod CIDRs"}) {
		t.Fatalf("partial %+v", got)
	}
}
