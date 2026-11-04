package integration

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func cidrNode(name string, cidrs ...string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.NodeSpec{PodCIDRs: cidrs}}
}

func serviceCIDR(cidrs ...string) *networkingv1.ServiceCIDR {
	return &networkingv1.ServiceCIDR{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: cidrs}}
}

func TestClusterCIDRsSources(t *testing.T) {
	ctx := context.Background()
	kubeadm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "kubeadm-config", Namespace: "kube-system"},
		Data: map[string]string{"ClusterConfiguration": "networking:\n  podSubnet: 10.244.0.0/16,fd00:10:244::/56\n  serviceSubnet: 10.96.0.0/16\n"}}
	read := func(objects ...runtime.Object) cidrRead {
		var r ClusterCIDRReader
		got, err := r.Read(ctx, fake.NewSimpleClientset(objects...))
		return cidrRead{got.Pods, got.Services, got.Missing, err}
	}

	// Nodes and ServiceCIDR objects come first.
	got := read(cidrNode("a", "10.244.1.0/24"), cidrNode("b", "10.244.2.0/24"), kubeadm, serviceCIDR("10.96.0.0/12"))
	if !reflect.DeepEqual(got.pods, []string{"10.244.1.0/24", "10.244.2.0/24"}) || !reflect.DeepEqual(got.services, []string{"10.96.0.0/12"}) || len(got.missing) != 0 || got.err != nil {
		t.Fatalf("primary sources %+v", got)
	}
	// Without them, kubeadm-config.
	got = read(cidrNode("a"), kubeadm)
	if !reflect.DeepEqual(got.pods, []string{"10.244.0.0/16", "fd00:10:244::/56"}) || !reflect.DeepEqual(got.services, []string{"10.96.0.0/16"}) || got.err != nil {
		t.Fatalf("kubeadm fallback %+v", got)
	}
	// A VPC-routed CNI on a managed cluster: every source answers, nothing
	// for pods. That is Missing, not an error.
	got = read(cidrNode("a"), serviceCIDR("172.20.0.0/16"))
	if len(got.pods) != 0 || !reflect.DeepEqual(got.missing, []string{"pod CIDRs"}) || got.err != nil {
		t.Fatalf("partial %+v", got)
	}
}

// cidrRead flattens one read for the table checks.
type cidrRead struct {
	pods, services, missing []string
	err                     error
}

func TestClusterCIDRsKeepLastGoodValue(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(cidrNode("a", "10.244.0.0/24"), serviceCIDR("10.96.0.0/12"))
	failing := map[string]bool{}
	for _, resource := range []string{"nodes", "servicecidrs", "configmaps"} {
		resource := resource
		client.PrependReactor("*", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			if failing[resource] {
				return true, nil, errors.New("apiserver unavailable")
			}
			return false, nil, nil
		})
	}
	var r ClusterCIDRReader

	// No source has answered yet: both parts are Missing, and the error says so.
	failing["nodes"], failing["servicecidrs"], failing["configmaps"] = true, true, true
	got, err := r.Read(ctx, client)
	if err == nil || !reflect.DeepEqual(got.Missing, []string{"pod CIDRs", "service CIDRs"}) {
		t.Fatalf("never answered: %+v %v", got, err)
	}
	failing["nodes"], failing["servicecidrs"], failing["configmaps"] = false, false, false
	want, err := r.Read(ctx, client)
	if err != nil || len(want.Missing) != 0 {
		t.Fatalf("good read %+v %v", want, err)
	}
	// A failed read keeps the last good value of the part that failed.
	failing["nodes"], failing["configmaps"] = true, true
	got, err = r.Read(ctx, client)
	if err == nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("failed pod read must keep the last good value: %+v %v, want %+v", got, err, want)
	}
	failing["nodes"], failing["servicecidrs"] = false, true
	got, err = r.Read(ctx, client)
	if err == nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("failed service read must keep the last good value: %+v %v, want %+v", got, err, want)
	}
}

func TestClusterCIDRsAggregate(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		// Two halves of one prefix become that prefix, repeatedly.
		{[]string{"10.244.1.0/24", "10.244.0.0/24", "10.244.2.0/24", "10.244.3.0/24"}, []string{"10.244.0.0/22"}},
		// Not halves of one prefix: kept, never widened.
		{[]string{"10.244.1.0/24", "10.244.2.0/24"}, []string{"10.244.1.0/24", "10.244.2.0/24"}},
		// Contained and duplicate prefixes go; families stay apart.
		{[]string{"10.244.0.0/16", "10.244.7.0/24", "10.244.0.0/16", "fd00:10:244::/64", "fd00:10:244:1::/64"}, []string{"10.244.0.0/16", "fd00:10:244::/63"}},
		{[]string{"0.0.0.0/0", "10.0.0.0/8"}, []string{"0.0.0.0/0"}},
		{nil, []string{}},
	} {
		if got := aggregate(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("aggregate(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// A node that joins inside an already covered range does not change the class.
	ctx := context.Background()
	var r ClusterCIDRReader
	nodes := []runtime.Object{cidrNode("a", "10.244.0.0/24"), cidrNode("b", "10.244.1.0/24"), serviceCIDR("10.96.0.0/12")}
	before, _ := r.Read(ctx, fake.NewSimpleClientset(nodes...))
	after, _ := r.Read(ctx, fake.NewSimpleClientset(append(nodes, cidrNode("c", "10.244.1.128/25"))...))
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(after.Pods, []string{"10.244.0.0/23"}) {
		t.Fatalf("before %+v after %+v", before, after)
	}
}
