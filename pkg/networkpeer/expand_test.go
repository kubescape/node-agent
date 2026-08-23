package networkpeer

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func port(name string, p int32) v1beta1.NetworkPort {
	return v1beta1.NetworkPort{Name: name, Protocol: "TCP", Port: &p}
}

// TestExpandServiceNeighbors_Egress: a serviceRef (alertmanager) + a host
// entity neighbor expand into selector-free ipAddresses neighbors carrying the
// resolved IPs and the original ports; a plain ipAddresses neighbor and an
// unresolvable serviceRef contribute nothing.
func TestExpandServiceNeighbors_Egress(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{
		{Identifier: "am", Type: "internal", ServiceRefNamespace: "honey", ServiceRefName: "alertmanager", Ports: []v1beta1.NetworkPort{port("TCP-9093", 9093)}},
		{Identifier: "plain", Type: "internal", IPAddresses: []string{"10.43.0.0/16"}, Ports: []v1beta1.NetworkPort{port("TCP-443", 443)}},
		{Identifier: "ghost", Type: "internal", ServiceRefNamespace: "honey", ServiceRefName: "missing", Ports: []v1beta1.NetworkPort{port("TCP-1", 1)}},
	}
	out := ExpandServiceNeighbors(in, l)

	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized neighbor (alertmanager only), got %d", len(out))
	}
	got := out[0]
	if got.Identifier != "am-resolved" {
		t.Errorf("identifier: got %q", got.Identifier)
	}
	// ClusterIP + both endpoints, port carried over.
	wantIPs := map[string]bool{"10.43.54.190": false, "10.42.0.44": false, "10.42.0.84": false}
	for _, ip := range got.IPAddresses {
		if _, ok := wantIPs[ip]; !ok {
			t.Errorf("unexpected resolved IP %s", ip)
		}
		wantIPs[ip] = true
	}
	for ip, seen := range wantIPs {
		if !seen {
			t.Errorf("missing resolved IP %s", ip)
		}
	}
	if len(got.Ports) != 1 || got.Ports[0].Port == nil || *got.Ports[0].Port != 9093 {
		t.Errorf("ports not carried over: %+v", got.Ports)
	}
}

// TestExpandServiceNeighbors_HostEntity: fromEntity host resolves to node +
// gateway IPs on the health port.
func TestExpandServiceNeighbors_HostEntity(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{
		{Identifier: "probes", Type: "internal", Entity: "host", Ports: []v1beta1.NetworkPort{port("TCP-9440", 9440)}},
	}
	out := ExpandServiceNeighbors(in, l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized host neighbor, got %d", len(out))
	}
	// Feed the synthesized entry through the address matcher the same way the
	// projection would, to prove end-to-end intent.
	tuples := Resolve(PeerSpec{Entity: "host", Ports: []PortProto{{Port: 9440, Protocol: "TCP"}}}, l)
	if !Matches(tuples, "10.42.0.1", 9440, "TCP") {
		t.Errorf("gateway kubelet probe should match")
	}
	if Matches(tuples, "10.42.0.1", 9090, "TCP") {
		t.Errorf("wrong port must not match")
	}
}

// TestExpandServiceNeighbors_Selector: serviceSelector expands across all
// matching Services in the scoped namespace.
func TestExpandServiceNeighbors_Selector(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{{
		Identifier:        "guestbooks",
		Type:              "internal",
		ServiceSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guestbook"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"}},
		Ports:             []v1beta1.NetworkPort{port("TCP-80", 80)},
	}}
	out := ExpandServiceNeighbors(in, l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized neighbor, got %d", len(out))
	}
	if len(out[0].IPAddresses) != 2 {
		t.Errorf("expected 2 guestbook ClusterIPs, got %v", out[0].IPAddresses)
	}
}

// TestExpandServiceNeighbors_NilLister: no cluster view, no expansion.
func TestExpandServiceNeighbors_NilLister(t *testing.T) {
	in := []v1beta1.NetworkNeighbor{{Identifier: "am", Entity: "host"}}
	if out := ExpandServiceNeighbors(in, nil); out != nil {
		t.Errorf("nil lister must expand to nil, got %v", out)
	}
}

// TestExpandServiceNeighbors_SelectorFailClosed: a serviceSelector carrying
// MatchExpressions (unsupported) or an empty matchLabels must NOT broaden the
// allowlist — it resolves to nothing.
func TestExpandServiceNeighbors_SelectorFailClosed(t *testing.T) {
	l := realFluxTopology()
	cases := []v1beta1.NetworkNeighbor{
		{Identifier: "expr", ServiceSelector: &metav1.LabelSelector{
			MatchLabels:      map[string]string{"app": "guestbook"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}},
		}, Ports: []v1beta1.NetworkPort{port("TCP-80", 80)}},
		{Identifier: "empty", ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{}}, Ports: []v1beta1.NetworkPort{port("TCP-80", 80)}},
	}
	for _, n := range cases {
		if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{n}, l); len(out) != 0 {
			t.Errorf("%s: selector must fail closed, got %d", n.Identifier, len(out))
		}
	}
}

// TestWithResolvedServiceNeighbors: the CP-level wrapper appends resolved
// neighbors without mutating the input, and is a no-op when nothing resolves.
func TestWithResolvedServiceNeighbors(t *testing.T) {
	l := realFluxTopology()
	cp := &v1beta1.ContainerProfile{}
	cp.Spec.Egress = []v1beta1.NetworkNeighbor{
		{Identifier: "am", ServiceRefNamespace: "honey", ServiceRefName: "alertmanager", Ports: []v1beta1.NetworkPort{port("TCP-9093", 9093)}},
	}
	cp.Spec.Ingress = []v1beta1.NetworkNeighbor{
		{Identifier: "probes", Entity: "host", Ports: []v1beta1.NetworkPort{port("TCP-9440", 9440)}},
	}
	out := WithResolvedServiceNeighbors(cp, l)

	if len(cp.Spec.Egress) != 1 || len(cp.Spec.Ingress) != 1 {
		t.Fatalf("input CP must not be mutated: eg=%d in=%d", len(cp.Spec.Egress), len(cp.Spec.Ingress))
	}
	if len(out.Spec.Egress) != 2 {
		t.Errorf("egress: want original + 1 resolved, got %d", len(out.Spec.Egress))
	}
	if len(out.Spec.Ingress) != 2 {
		t.Errorf("ingress: want original + 1 resolved, got %d", len(out.Spec.Ingress))
	}

	// No-op cases.
	if got := WithResolvedServiceNeighbors(cp, nil); got != cp {
		t.Error("nil lister must return the same CP unchanged")
	}
	plain := &v1beta1.ContainerProfile{}
	plain.Spec.Egress = []v1beta1.NetworkNeighbor{{Identifier: "ip", IPAddresses: []string{"10.0.0.0/8"}}}
	if got := WithResolvedServiceNeighbors(plain, l); got != plain {
		t.Error("a CP with no service/entity neighbors must return unchanged (same pointer)")
	}
}

// TestExpandServiceNeighbors_NamespaceSelectorFailClosed: a namespaceSelector
// is honored only as the single equality kubernetes.io/metadata.name=<ns>; any
// other form must fail closed rather than silently broaden cluster-wide.
func TestExpandServiceNeighbors_NamespaceSelectorFailClosed(t *testing.T) {
	l := realFluxTopology()
	withNS := func(nsSel *metav1.LabelSelector) v1beta1.NetworkNeighbor {
		return v1beta1.NetworkNeighbor{
			Identifier:        "svc",
			ServiceSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guestbook"}},
			NamespaceSelector: nsSel,
			Ports:             []v1beta1.NetworkPort{port("TCP-80", 80)},
		}
	}
	bad := []*metav1.LabelSelector{
		{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpExists}}},
		{MatchLabels: map[string]string{"env": "prod"}},                                          // wrong key
		{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo", "x": "y"}}, // extra key
		{MatchLabels: map[string]string{}},                                                       // empty
	}
	for i, ns := range bad {
		if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{withNS(ns)}, l); len(out) != 0 {
			t.Errorf("bad namespaceSelector[%d] must fail closed, got %d", i, len(out))
		}
	}
	good := withNS(&metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"}})
	if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{good}, l); len(out) != 1 {
		t.Errorf("metadata.name namespaceSelector should resolve, got %d", len(out))
	}
}

// TestHasServiceNeighbors: a profile with a serviceRef/serviceSelector/entity
// neighbor is flagged as depending on the live cluster view; a plain
// ipAddresses/dnsNames profile is not.
func TestHasServiceNeighbors(t *testing.T) {
	if HasServiceNeighbors(nil) {
		t.Error("nil CP must be false")
	}
	plain := &v1beta1.ContainerProfile{}
	plain.Spec.Egress = []v1beta1.NetworkNeighbor{{Identifier: "ip", IPAddresses: []string{"10.0.0.0/8"}}}
	if HasServiceNeighbors(plain) {
		t.Error("plain ipAddresses profile must not use service resolution")
	}
	for _, n := range []v1beta1.NetworkNeighbor{
		{ServiceRefName: "alertmanager", ServiceRefNamespace: "honey"},
		{ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}},
		{Entity: "host"},
	} {
		cp := &v1beta1.ContainerProfile{}
		cp.Spec.Ingress = []v1beta1.NetworkNeighbor{n}
		if !HasServiceNeighbors(cp) {
			t.Errorf("neighbor %+v should be flagged", n)
		}
	}
}
