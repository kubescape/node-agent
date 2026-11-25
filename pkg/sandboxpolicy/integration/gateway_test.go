package integration

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/httpgateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func gatewayTestPod(name string, labels map[string]string, mutate func(*corev1.Pod)) *corev1.Pod {
	controller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID("uid-" + name), Labels: labels,
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "app-5d4f8c", Controller: &controller}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "main"}, {Name: "side"}}, InitContainers: []corev1.Container{{Name: "init"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, QOSClass: corev1.PodQOSBurstable},
	}
	if mutate != nil {
		mutate(pod)
	}
	return pod
}

// stubPolicies returns HTTPPolicy values through the controller's own parser,
// so Selects behaves as in production.
func stubPolicies(t *testing.T, policies ...sandboxpolicy.HTTPPolicyForTest) []sandboxpolicy.HTTPPolicy {
	t.Helper()
	out, err := sandboxpolicy.HTTPPoliciesForTest(policies...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGatewayPods(t *testing.T) {
	policies := stubPolicies(t,
		sandboxpolicy.HTTPPolicyForTest{UID: "p-app", Namespace: "ns", Generation: 3, PodLabels: map[string]string{"app": "agent"}, Containers: []string{"main"}},
		sandboxpolicy.HTTPPolicyForTest{UID: "p-deny", Namespace: "ns", Generation: 1, PodLabels: map[string]string{"tier": "strict"}, Containers: []string{"*"}, Deny: true},
		sandboxpolicy.HTTPPolicyForTest{UID: "p-off", Namespace: "ns", Generation: 9, PodLabels: map[string]string{"app": "agent"}, Containers: []string{"*"}, Off: true},
		sandboxpolicy.HTTPPolicyForTest{UID: "p-init-only", Namespace: "ns", Generation: 1, PodLabels: map[string]string{"app": "batch"}, Containers: []string{"init"}},
		sandboxpolicy.HTTPPolicyForTest{UID: "p-other-ns", Namespace: "elsewhere", Generation: 1, PodLabels: map[string]string{"app": "agent"}, Containers: []string{"*"}},
		sandboxpolicy.HTTPPolicyForTest{UID: "p-cluster", Generation: 2, PodLabels: map[string]string{"app": "agent"}, NamespaceLabels: map[string]string{"sandboxed": "yes"}, Containers: []string{"*"}},
	)
	pods := []*corev1.Pod{
		gatewayTestPod("agent", map[string]string{"app": "agent", "tier": "strict", "pod-template-hash": "5d4f8c"}, func(p *corev1.Pod) {
			p.Annotations = map[string]string{httpgateway.PreparedAnnotation: "aa11,bb22"}
		}),
		gatewayTestPod("hostnet", map[string]string{"app": "agent"}, func(p *corev1.Pod) {
			p.Spec.HostNetwork = true
			p.OwnerReferences[0].Kind, p.OwnerReferences[0].Name = "DaemonSet", "ds"
		}),
		gatewayTestPod("batch", map[string]string{"app": "batch"}, func(p *corev1.Pod) { p.OwnerReferences = nil }),
		gatewayTestPod("unselected", map[string]string{"app": "web"}, nil),
		gatewayTestPod("finished", map[string]string{"app": "agent"}, func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }),
	}
	containers := []gatewayContainer{
		{PodUID: "uid-agent", Name: "side", CgroupID: 12, PID: 2002},
		{PodUID: "uid-agent", Name: "main", CgroupID: 11, PID: 2001},
		{PodUID: "uid-hostnet", Name: "main", CgroupID: 21, PID: 3001},
		{PodUID: "uid-unselected", Name: "main", CgroupID: 31, PID: 4001},
		{PodUID: "", Name: "main", CgroupID: 41, PID: 5001}, // not enriched yet
	}
	podCgroup := func(p *corev1.Pod) uint64 {
		if p.Name == "agent" {
			return 10
		}
		return 0
	}
	got := gatewayPods(pods, map[string]map[string]string{"ns": {"sandboxed": "yes"}}, policies, containers, podCgroup, "/host/proc")

	ref := func(uid string, generation int64) httpgateway.PolicyRef {
		return httpgateway.PolicyRef{UID: uid, Generation: generation}
	}
	want := []httpgateway.Pod{
		{UID: "uid-agent", Namespace: "ns", Name: "agent", ControllerKind: "Deployment", ControllerName: "app", Prepared: "aa11,bb22",
			Policies:  []httpgateway.Policy{{Ref: ref("p-app", 3)}, {Ref: ref("p-cluster", 2)}, {Ref: ref("p-deny", 1), Deny: true}, {Ref: ref("p-off", 9), Off: true}},
			PodCgroup: 10, Containers: map[string]uint64{"main": 11, "side": 12}, NetNS: "/host/proc/2001/ns/net"},
		{UID: "uid-batch", Namespace: "ns", Name: "batch", Policies: []httpgateway.Policy{{Ref: ref("p-init-only", 1)}}, Containers: map[string]uint64{}},
		{UID: "uid-hostnet", Namespace: "ns", Name: "hostnet", ControllerKind: "DaemonSet", ControllerName: "ds",
			Policies:   []httpgateway.Policy{{Ref: ref("p-app", 3)}, {Ref: ref("p-cluster", 2)}, {Ref: ref("p-off", 9), Off: true}},
			Containers: map[string]uint64{"main": 21}, HostNetwork: true},
	}
	if !reflect.DeepEqual(got, want) {
		for i := range got {
			if i < len(want) && !reflect.DeepEqual(got[i], want[i]) {
				t.Errorf("pod %d:\n got %+v\nwant %+v", i, got[i], want[i])
			}
		}
		t.Fatalf("got %d pods, want %d", len(got), len(want))
	}

	// With these inputs the binding rule gives: the agent pod bound with
	// posture deny, the batch pod waiting for a restart.
	d := httpgateway.Decide(got[0], "aa11", httpgateway.Rotation{}, metav1.Now().Time)
	if !d.Bound || d.Posture != httpgateway.PostureDeny || len(d.Policies) != 3 {
		t.Errorf("agent pod: %+v", d)
	}
	if d := httpgateway.Decide(got[1], "aa11", httpgateway.Rotation{}, metav1.Now().Time); d.Bound || !d.NeedRestart {
		t.Errorf("batch pod: %+v", d)
	}
}

func TestNodeIPv4(t *testing.T) {
	node := &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
		{Type: corev1.NodeExternalIP, Address: "198.51.100.7"},
		{Type: corev1.NodeInternalIP, Address: "fd00::10"},
		{Type: corev1.NodeInternalIP, Address: "192.168.1.10"},
	}}}
	if got, ok := nodeIPv4(node); !ok || got != netip.MustParseAddr("192.168.1.10") {
		t.Errorf("got %v %v", got, ok)
	}
	if _, ok := nodeIPv4(&corev1.Node{}); ok {
		t.Error("a node with no address has an IPv4 address")
	}
}

func TestRetryGateway(t *testing.T) {
	first, maxWait := gatewayRetryFirst, gatewayRetryMax
	gatewayRetryFirst, gatewayRetryMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { gatewayRetryFirst, gatewayRetryMax = first, maxWait })

	// Fails three times (the node read during an API server outage), then
	// starts: the loop stops at the first success.
	attempts := 0
	var reports []string
	retryGateway(context.Background(), func(context.Context) error {
		attempts++
		if attempts <= 3 {
			return errors.New("api server away")
		}
		return nil
	}, func(err error) { reports = append(reports, err.Error()) })
	if attempts != 4 || len(reports) != 3 {
		t.Errorf("%d attempts, %d reports %v; want 4 and 3", attempts, len(reports), reports)
	}
	for i, want := range []string{"retrying in 1ms", "retrying in 2ms", "retrying in 4ms"} {
		if i < len(reports) && !strings.Contains(reports[i], want) {
			t.Errorf("report %d %q, want %q", i, reports[i], want)
		}
	}

	// Cancelled while waiting: it returns.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		retryGateway(ctx, func(context.Context) error { return errors.New("down") }, func(error) {})
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("retryGateway did not stop after cancel")
	}
}
