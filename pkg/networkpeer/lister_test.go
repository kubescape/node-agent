package networkpeer

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

// newTestLister builds an InformerLister over a fake cluster seeded from the
// real flux/kubescape topology, exercising the production Service/EndpointSlice/
// Node -> Lister path (not the hand-written fake used by the resolver tests).
func newTestLister(t *testing.T) *InformerLister {
	t.Helper()
	client := fake.NewClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "honey", Name: "alertmanager", Labels: map[string]string{"app": "alertmanager"}},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.43.54.190", ClusterIPs: []string{"10.43.54.190"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: "honey", Name: "alertmanager-x1", Labels: map[string]string{discoveryv1.LabelServiceName: "alertmanager"}},
			Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.42.0.44", "10.42.0.84"}}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "gitops-demo", Name: "guestbook-ui", Labels: map[string]string{"app": "guestbook"}},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.43.111.192", ClusterIPs: []string{"10.43.111.192"}},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "tanzee"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.42.0.0/24", PodCIDRs: []string{"10.42.0.0/24"}},
			Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.191"}}},
		},
		&corev1.Node{ // a second node whose IPs must NOT leak into this node's "host"
			ObjectMeta: metav1.ObjectMeta{Name: "other"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.42.9.0/24", PodCIDRs: []string{"10.42.9.0/24"}},
			Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.0.99"}}},
		},
	)
	factory := informers.NewSharedInformerFactory(client, 0)
	l := NewInformerLister(
		factory.Core().V1().Services().Lister(),
		factory.Discovery().V1().EndpointSlices().Lister(),
		factory.Core().V1().Nodes().Lister(),
		"tanzee",
	)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	factory.Start(stop)
	factory.WaitForCacheSync(stop)
	return l
}

func TestInformerLister_ServiceByName(t *testing.T) {
	l := newTestLister(t)
	svc, ok := l.ServiceByName("honey", "alertmanager")
	if !ok {
		t.Fatal("alertmanager Service should resolve")
	}
	if len(svc.ClusterIPs) != 1 || svc.ClusterIPs[0] != "10.43.54.190" {
		t.Errorf("ClusterIPs: got %v", svc.ClusterIPs)
	}
	if len(svc.EndpointIPs) != 2 {
		t.Errorf("EndpointIPs: got %v (want 2 from the EndpointSlice)", svc.EndpointIPs)
	}
	// End-to-end through the resolver, like the projection will.
	tuples := Resolve(PeerSpec{ServiceRef: &ServiceRef{"honey", "alertmanager"}, Ports: []PortProto{{Port: 9093, Protocol: "TCP"}}}, l)
	if !Matches(tuples, "10.43.54.190", 9093, "TCP") || !Matches(tuples, "10.42.0.44", 9093, "TCP") {
		t.Errorf("resolver over informer lister should match ClusterIP + endpoints")
	}
	if _, ok := l.ServiceByName("honey", "nope"); ok {
		t.Error("unknown Service must not resolve")
	}
}

func TestInformerLister_HostIPs(t *testing.T) {
	l := newTestLister(t)
	ips := l.HostIPs()
	want := map[string]bool{"192.168.0.191": false}
	for _, ip := range ips {
		if _, ok := want[ip]; ok {
			want[ip] = true
		}
	}
	for ip, seen := range want {
		if !seen {
			t.Errorf("HostIPs missing %s (got %v)", ip, ips)
		}
	}
	for _, ip := range ips {
		if ip == "192.168.0.99" {
			t.Errorf("HostIPs must be scoped to the local node; leaked other node's %s", ip)
		}
	}
}

// TestInformerLister_EmptySelectorFailsClosed: an empty serviceSelector must
// NOT resolve to every Service in the cluster.
func TestInformerLister_EmptySelectorFailsClosed(t *testing.T) {
	l := newTestLister(t)
	if got := l.ServicesByLabels(map[string]string{}, nil); len(got) != 0 {
		t.Errorf("empty selector must fail closed, got %d services", len(got))
	}
	if got := Resolve(PeerSpec{ServiceSelector: map[string]string{}, Ports: tcp(80)}, l); len(got) != 0 {
		t.Errorf("Resolve with empty selector must yield nothing, got %v", got)
	}
}

func TestInformerLister_ServicesByLabels(t *testing.T) {
	l := newTestLister(t)
	svcs := l.ServicesByLabels(map[string]string{"app": "guestbook"}, map[string]string{"kubernetes.io/metadata.name": "gitops-demo"})
	if len(svcs) != 1 || svcs[0].Name != "guestbook-ui" {
		t.Fatalf("expected guestbook-ui, got %v", svcs)
	}
	// Namespace scoping excludes a same-label service elsewhere (none here) and
	// a wrong-namespace filter yields nothing.
	if got := l.ServicesByLabels(map[string]string{"app": "guestbook"}, map[string]string{"kubernetes.io/metadata.name": "other"}); len(got) != 0 {
		t.Errorf("namespace filter should exclude, got %v", got)
	}
}

func TestTrimEndpointSlice_PreservesReady(t *testing.T) {
	ready := true
	unready := false
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "slice1",
			Namespace:       "default",
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "test"}},
			Annotations:     map[string]string{"foo": "bar"},
			ResourceVersion: "123",
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &unready}},
			{Addresses: []string{"10.0.0.3"}, Conditions: discoveryv1.EndpointConditions{Ready: nil}},
		},
	}
	trimmedObj, err := TrimEndpointSlice(es)
	if err != nil {
		t.Fatalf("TrimEndpointSlice failed: %v", err)
	}
	trimmed := trimmedObj.(*discoveryv1.EndpointSlice)
	if trimmed.ManagedFields != nil || trimmed.Annotations != nil {
		t.Errorf("expected managedFields and annotations to be stripped")
	}
	if len(trimmed.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(trimmed.Endpoints))
	}
	if trimmed.Endpoints[0].Conditions.Ready == nil || !*trimmed.Endpoints[0].Conditions.Ready {
		t.Errorf("endpoint 0 ready condition lost")
	}
	if trimmed.Endpoints[1].Conditions.Ready == nil || *trimmed.Endpoints[1].Conditions.Ready {
		t.Errorf("endpoint 1 unready condition lost")
	}
	if trimmed.Endpoints[2].Conditions.Ready != nil {
		t.Errorf("endpoint 2 nil ready condition should remain nil")
	}
}

func TestInformerLister_EndpointReadiness(t *testing.T) {
	ready := true
	unready := false
	client := fake.NewClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.43.0.1"},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api-1", Labels: map[string]string{discoveryv1.LabelServiceName: "api"}},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.42.1.10"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
				{Addresses: []string{"10.42.1.11"}, Conditions: discoveryv1.EndpointConditions{Ready: &unready}},
				{Addresses: []string{"10.42.1.12"}, Conditions: discoveryv1.EndpointConditions{Ready: nil}}, // nil is treated as ready
			},
		},
	)
	factory := informers.NewSharedInformerFactory(client, 0)
	l := NewInformerLister(
		factory.Core().V1().Services().Lister(),
		factory.Discovery().V1().EndpointSlices().Lister(),
		factory.Core().V1().Nodes().Lister(),
		"",
	)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	factory.Start(stop)
	factory.WaitForCacheSync(stop)

	svc, ok := l.ServiceByName("prod", "api")
	if !ok {
		t.Fatalf("expected api service to resolve")
	}
	// 10.42.1.10 (ready) and 10.42.1.12 (nil) should be present; 10.42.1.11 (unready) excluded.
	wantEndpoints := []string{"10.42.1.10", "10.42.1.12"}
	if len(svc.EndpointIPs) != len(wantEndpoints) || svc.EndpointIPs[0] != wantEndpoints[0] || svc.EndpointIPs[1] != wantEndpoints[1] {
		t.Errorf("got EndpointIPs %v, want %v", svc.EndpointIPs, wantEndpoints)
	}
}

func TestInformerLister_Generation(t *testing.T) {
	l := newTestLister(t)
	g0 := l.Generation()
	l.Bump()
	l.Bump()
	if l.Generation() != g0+2 {
		t.Errorf("Generation must advance on Bump: got %d want %d", l.Generation(), g0+2)
	}
}
