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
	out := ExpandServiceNeighbors(in, "", l)

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
	// serviceRef implies the Service cluster FQDN as a dnsName (R0005 suppression).
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "alertmanager.honey.svc.cluster.local" {
		t.Errorf("serviceRef FQDN not emitted: %v", got.DNSNames)
	}
}

// TestExpandServiceNeighbors_HostEntity: fromEntity host resolves to node +
// gateway IPs on the health port.
func TestExpandServiceNeighbors_HostEntity(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{
		{Identifier: "probes", Type: "internal", Entity: "host", Ports: []v1beta1.NetworkPort{port("TCP-9440", 9440)}},
	}
	out := ExpandServiceNeighbors(in, "", l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized host neighbor, got %d", len(out))
	}
	// host entity is not a Service: no FQDN.
	if len(out[0].DNSNames) != 0 {
		t.Errorf("host entity must not emit a dnsName: %v", out[0].DNSNames)
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
	out := ExpandServiceNeighbors(in, "", l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized neighbor, got %d", len(out))
	}
	if len(out[0].IPAddresses) != 2 {
		t.Errorf("expected 2 guestbook ClusterIPs, got %v", out[0].IPAddresses)
	}
}

func TestExpandServiceNeighbors_NoPortsMeansAnyPort(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{
		{Identifier: "st", Type: "internal", ServiceRefNamespace: "honey", ServiceRefName: "storage"},
	}
	out := ExpandServiceNeighbors(in, "", l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized neighbor, got %d", len(out))
	}
	if len(out[0].Ports) != 0 {
		t.Errorf("a portless source neighbor must synthesize a portless (any-port) entry, got %+v", out[0].Ports)
	}
	if len(out[0].IPAddresses) != 1 || out[0].IPAddresses[0] != "10.43.70.156" {
		t.Errorf("storage ClusterIP expected, got %v", out[0].IPAddresses)
	}
}

func TestExpandServiceNeighbors_SelectorFQDNFanout(t *testing.T) {
	l := realFluxTopology()
	in := []v1beta1.NetworkNeighbor{{
		Identifier:        "guestbooks",
		Type:              "internal",
		ServiceSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guestbook"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"}},
		Ports:             []v1beta1.NetworkPort{port("TCP-80", 80)},
	}}
	out := ExpandServiceNeighbors(in, "", l)
	if len(out) != 1 {
		t.Fatalf("expected 1 synthesized neighbor, got %d", len(out))
	}
	want := map[string]bool{"guestbook-ui.gitops-demo.svc.cluster.local": false, "helm-guestbook.gitops-demo.svc.cluster.local": false}
	for _, d := range out[0].DNSNames {
		if _, ok := want[d]; !ok {
			t.Errorf("unexpected FQDN %s", d)
		}
		want[d] = true
	}
	for d, seen := range want {
		if !seen {
			t.Errorf("selector fanout must imply FQDN %s, got %v", d, out[0].DNSNames)
		}
	}
}

// TestExpandServiceNeighbors_NilLister: no cluster view, no expansion.
func TestExpandServiceNeighbors_NilLister(t *testing.T) {
	in := []v1beta1.NetworkNeighbor{{Identifier: "am", Entity: "host"}}
	if out := ExpandServiceNeighbors(in, "", nil); out != nil {
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
		if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{n}, "", l); len(out) != 0 {
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
	}
	for i, ns := range bad {
		if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{withNS(ns)}, "", l); len(out) != 0 {
			t.Errorf("bad namespaceSelector[%d] must fail closed, got %d", i, len(out))
		}
	}
	good := withNS(&metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"}})
	if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{good}, "", l); len(out) != 1 {
		t.Errorf("metadata.name namespaceSelector should resolve, got %d", len(out))
	}
	// An explicit EMPTY {} namespaceSelector is cluster-wide (opt-in), NOT fail-closed.
	clusterWide := withNS(&metav1.LabelSelector{})
	if out := ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{clusterWide}, "gitops-demo", l); len(out) != 1 {
		t.Errorf("empty {} namespaceSelector must resolve cluster-wide, got %d", len(out))
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
	nsOnly := &v1beta1.ContainerProfile{}
	nsOnly.Spec.Ingress = []v1beta1.NetworkNeighbor{{ServiceRefNamespace: "honey"}}
	if HasServiceNeighbors(nsOnly) {
		t.Error("ServiceRefNamespace without ServiceRefName must not be flagged (specFromNeighbor rejects it)")
	}
}

// WithHostPeer injects entity:host into both directions; after resolution the
// node's InternalIP and CNI gateway land in the address surface, so node-IP
// traffic (kubelet probes, hostNetwork peers) is covered by the address matcher
// and never alerts — the default host-peer allowlist (alertOnHostPeers=false).
func TestWithHostPeer_ResolvesNodeIPsIntoAddressSurface(t *testing.T) {
	l := realFluxTopology() // hostIPs: node 192.168.0.191, gateway 10.42.0.1
	cp := &v1beta1.ContainerProfile{}

	withHost := WithResolvedServiceNeighbors(WithHostPeer(cp), l)

	collect := func(ns []v1beta1.NetworkNeighbor) map[string]bool {
		s := map[string]bool{}
		for i := range ns {
			for _, ip := range ns[i].IPAddresses {
				s[ip] = true
			}
		}
		return s
	}
	for _, dir := range []struct {
		name string
		ns   []v1beta1.NetworkNeighbor
	}{{"egress", withHost.Spec.Egress}, {"ingress", withHost.Spec.Ingress}} {
		got := collect(dir.ns)
		for _, ip := range []string{"192.168.0.191", "10.42.0.1"} {
			if !got[ip] {
				t.Errorf("%s: node IP %s must resolve into the address surface, got %v", dir.name, ip, got)
			}
		}
	}
}

// A nil profile is a no-op, and WithHostPeer must not mutate its input.
func TestWithHostPeer_NilAndNoMutation(t *testing.T) {
	if WithHostPeer(nil) != nil {
		t.Error("WithHostPeer(nil) must be nil")
	}
	cp := &v1beta1.ContainerProfile{Spec: v1beta1.ContainerProfileSpec{Egress: []v1beta1.NetworkNeighbor{{Identifier: "keep"}}}}
	_ = WithHostPeer(cp)
	if len(cp.Spec.Egress) != 1 || len(cp.Spec.Ingress) != 0 {
		t.Errorf("WithHostPeer must not mutate the input; egress=%d ingress=%d", len(cp.Spec.Egress), len(cp.Spec.Ingress))
	}
}
