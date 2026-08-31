package networkpeer

import (
	"sort"
	"testing"
)

// fakeLister is a static cluster view seeded from the real Flux/kubescape
// topology observed on the k3s dev cluster (issue #92). It lets the resolver
// tests assert against genuine ClusterIPs/endpoints without a live cluster.
type fakeLister struct {
	services map[string]*ServiceInfo // key "ns/name"
	hostIPs  []string
}

func (f *fakeLister) ServiceByName(ns, name string) (*ServiceInfo, bool) {
	s, ok := f.services[ns+"/"+name]
	return s, ok
}

func (f *fakeLister) ServicesByLabels(sel, nsLabels map[string]string) []*ServiceInfo {
	var out []*ServiceInfo
	for _, s := range f.services {
		if nsLabels != nil {
			if s.Labels["__ns__"] != nsLabels["kubernetes.io/metadata.name"] {
				continue
			}
		}
		if labelsSubset(sel, s.Labels) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (f *fakeLister) HostIPs() []string { return f.hostIPs }

func (f *fakeLister) Generation() int64 { return 0 }

func labelsSubset(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// realFluxTopology mirrors what `kubectl get svc/endpoints` returned live.
func realFluxTopology() *fakeLister {
	return &fakeLister{
		hostIPs: []string{"192.168.0.191", "10.42.0.1"}, // node InternalIP + CNI gateway
		services: map[string]*ServiceInfo{
			"honey/alertmanager": {
				Namespace: "honey", Name: "alertmanager",
				Labels:      map[string]string{"app": "alertmanager", "__ns__": "honey"},
				ClusterIPs:  []string{"10.43.54.190"},
				EndpointIPs: []string{"10.42.0.44", "10.42.0.84"},
			},
			"honey/storage": {
				Namespace: "honey", Name: "storage",
				Labels:     map[string]string{"app": "storage", "__ns__": "honey"},
				ClusterIPs: []string{"10.43.70.156"},
			},
			"default/kubernetes": { // k3s: apiserver endpoint is the node IP (Kind: Host)
				Namespace: "default", Name: "kubernetes",
				Labels:      map[string]string{"__ns__": "default"},
				ClusterIPs:  []string{"10.43.0.1"},
				EndpointIPs: []string{"192.168.0.191"},
			},
			"argocd/argocd-server": {
				Namespace: "argocd", Name: "argocd-server",
				Labels:     map[string]string{"app.kubernetes.io/name": "argocd-server", "__ns__": "argocd"},
				ClusterIPs: []string{"10.43.173.14"},
			},
			"gitops-demo/guestbook-ui": {
				Namespace: "gitops-demo", Name: "guestbook-ui",
				Labels:     map[string]string{"app": "guestbook", "__ns__": "gitops-demo"},
				ClusterIPs: []string{"10.43.111.192"},
			},
			"gitops-demo/helm-guestbook": {
				Namespace: "gitops-demo", Name: "helm-guestbook",
				Labels:     map[string]string{"app": "guestbook", "__ns__": "gitops-demo"},
				ClusterIPs: []string{"10.43.3.63"},
			},
		},
	}
}

func tcp(port int32) []PortProto { return []PortProto{{Port: port, Protocol: "TCP"}} }

// Test A1 — serviceRef egress (alertmanager) is narrow AND port-sensitive:
// matches its ClusterIP and endpoints on 9093 only; a sibling service on the
// same port stays visible to R0011 (the whole point vs a /16).
func TestServiceRef_Alertmanager(t *testing.T) {
	l := realFluxTopology()
	tuples := Resolve(PeerSpec{ServiceRef: &ServiceRef{"honey", "alertmanager"}, Ports: tcp(9093)}, l)

	cases := []struct {
		ip    string
		port  int32
		proto string
		want  bool
		why   string
	}{
		{"10.43.54.190", 9093, "TCP", true, "ClusterIP + port match"},
		{"10.42.0.44", 9093, "TCP", true, "backing endpoint IP"},
		{"10.42.0.84", 9093, "TCP", true, "backing endpoint IP"},
		{"10.43.54.190", 8080, "TCP", false, "wrong port (port-sensitive)"},
		{"10.43.54.190", 9093, "UDP", false, "wrong protocol"},
		{"10.43.173.14", 9093, "TCP", false, "argocd-server — different service, detection preserved"},
		{"10.43.70.156", 9093, "TCP", false, "storage — different service, detection preserved"},
	}
	for _, c := range cases {
		if got := Matches(tuples, c.ip, c.port, c.proto); got != c.want {
			t.Errorf("Matches(%s:%d/%s)=%v want %v (%s)", c.ip, c.port, c.proto, got, c.want, c.why)
		}
	}
}

// Test A2 — kube-apiserver needs no dedicated entity: toService default/kubernetes
// resolves to the ClusterIP AND the node-IP endpoint (k3s embeds the apiserver).
func TestServiceRef_KubeApiserver(t *testing.T) {
	l := realFluxTopology()
	tuples := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "kubernetes"}, Ports: tcp(443)}, l)
	for _, ip := range []string{"10.43.0.1", "192.168.0.191"} {
		if !Matches(tuples, ip, 443, "TCP") {
			t.Errorf("apiserver egress %s:443 should match via default/kubernetes", ip)
		}
	}
	if Matches(tuples, "10.43.0.1", 6443, "TCP") {
		t.Errorf("apiserver :6443 must not match (port 443 only)")
	}
}

// Test A3 — host entity: kubelet probe from the node/gateway matches on the
// health port only; a pod-CIDR source or wrong port does not.
func TestEntityHost(t *testing.T) {
	l := realFluxTopology()
	tuples := Resolve(PeerSpec{Entity: EntityHost, Ports: tcp(9440)}, l)
	if !Matches(tuples, "10.42.0.1", 9440, "TCP") {
		t.Errorf("kubelet probe 10.42.0.1:9440 should match fromEntity host")
	}
	if !Matches(tuples, "192.168.0.191", 9440, "TCP") {
		t.Errorf("node InternalIP :9440 should match fromEntity host")
	}
	if Matches(tuples, "10.42.0.1", 9090, "TCP") {
		t.Errorf("host :9090 must not match (port 9440 only)")
	}
	if Matches(tuples, "10.42.0.55", 9440, "TCP") {
		t.Errorf("a pod IP must not match fromEntity host")
	}
}

// Test A4 — serviceSelector fans out across all matching Services (the two
// gitops-demo guestbook services share app=guestbook), scoped by namespace.
func TestServiceSelector_GuestbookFanout(t *testing.T) {
	l := realFluxTopology()
	tuples := Resolve(PeerSpec{
		ServiceSelector: map[string]string{"app": "guestbook"},
		NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"},
		Ports:           tcp(80),
	}, l)
	for _, ip := range []string{"10.43.111.192", "10.43.3.63"} {
		if !Matches(tuples, ip, 80, "TCP") {
			t.Errorf("guestbook service %s:80 should match app=guestbook selector", ip)
		}
	}
	if Matches(tuples, "10.43.173.14", 80, "TCP") {
		t.Errorf("argocd-server must not match app=guestbook selector")
	}
}

// Test A5 — no accidental match-all: unknown service, unknown entity, and a
// selector matching nothing all resolve to zero tuples.
func TestResolve_NoMatchAll(t *testing.T) {
	l := realFluxTopology()
	specs := []PeerSpec{
		{ServiceRef: &ServiceRef{"honey", "does-not-exist"}, Ports: tcp(443)},
		{Entity: "world", Ports: tcp(443)},
		{ServiceSelector: map[string]string{"app": "nope"}, Ports: tcp(443)},
	}
	for i, s := range specs {
		if tuples := Resolve(s, l); len(tuples) != 0 {
			t.Errorf("spec[%d] should resolve to no tuples, got %d", i, len(tuples))
		}
	}
	if Matches(nil, "10.43.0.1", 443, "TCP") {
		t.Errorf("nil tuples must never match")
	}
}

// Test A7 — serviceRef/serviceSelector imply the Service cluster FQDN(s);
// entity and unresolvable specs imply none.
func TestResolveDNSNames(t *testing.T) {
	l := realFluxTopology()
	one := ResolveDNSNames(PeerSpec{ServiceRef: &ServiceRef{"honey", "alertmanager"}}, l)
	if len(one) != 1 || one[0] != "alertmanager.honey.svc.cluster.local" {
		t.Errorf("serviceRef FQDN: got %v", one)
	}
	fan := ResolveDNSNames(PeerSpec{
		ServiceSelector: map[string]string{"app": "guestbook"},
		NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "gitops-demo"},
	}, l)
	want := map[string]bool{"guestbook-ui.gitops-demo.svc.cluster.local": true, "helm-guestbook.gitops-demo.svc.cluster.local": true}
	if len(fan) != 2 || !want[fan[0]] || !want[fan[1]] {
		t.Errorf("selector FQDN fanout: got %v", fan)
	}
	if got := ResolveDNSNames(PeerSpec{Entity: EntityHost}, l); got != nil {
		t.Errorf("host entity implies no FQDN, got %v", got)
	}
	if got := ResolveDNSNames(PeerSpec{ServiceRef: &ServiceRef{"honey", "nope"}}, l); got != nil {
		t.Errorf("unresolvable serviceRef implies no FQDN, got %v", got)
	}
}

// Test A6 — a nil Lister and any-port (no Ports) behave safely.
func TestResolve_Edges(t *testing.T) {
	if got := Resolve(PeerSpec{Entity: EntityHost}, nil); got != nil {
		t.Errorf("nil lister must resolve to nil, got %v", got)
	}
	l := realFluxTopology()
	anyPort := Resolve(PeerSpec{ServiceRef: &ServiceRef{"honey", "storage"}}, l)
	if !Matches(anyPort, "10.43.70.156", 443, "TCP") || !Matches(anyPort, "10.43.70.156", 8443, "TCP") {
		t.Errorf("a serviceRef with no Ports should match any observed port on its IP")
	}
}

// TestServiceRef_TruthTable_KubeAPIServer is the full matrix for serviceRef
// resolution + matching, using the always-present default/kubernetes Service
// (the API server). Ports are the 443 the apiserver Service exposes; the
// resolved set is its ClusterIP plus its backing endpoint (the node IP on k3s).
func TestServiceRef_TruthTable_KubeAPIServer(t *testing.T) {
	l := realFluxTopology()
	const (
		clusterIP = "10.43.0.1"     // default/kubernetes ClusterIP
		endpoint  = "192.168.0.191" // apiserver backing endpoint (node IP)
	)

	// Ported serviceRef: 443/TCP only.
	tuples := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "kubernetes"}, Ports: tcp(443)}, l)
	grid := []struct {
		ip    string
		port  int32
		proto string
		want  bool
		why   string
	}{
		{clusterIP, 443, "TCP", true, "ClusterIP on the exposed port"},
		{endpoint, 443, "TCP", true, "backing endpoint (apiserver node) on the exposed port"},
		{clusterIP, 443, "tcp", true, "protocol match is case-insensitive"},
		{clusterIP, 6443, "TCP", false, "wrong port (port-sensitive)"},
		{clusterIP, 443, "UDP", false, "wrong protocol"},
		{"10.43.54.190", 443, "TCP", false, "a different Service's ClusterIP"},
		{"10.42.0.1", 443, "TCP", false, "the node gateway is not this Service"},
		{"10.42.0.55", 443, "TCP", false, "an unrelated pod IP"},
		{"", 443, "TCP", false, "empty IP never matches"},
	}
	for _, c := range grid {
		if got := Matches(tuples, c.ip, c.port, c.proto); got != c.want {
			t.Errorf("Matches(%q,%d,%s)=%v want %v — %s", c.ip, c.port, c.proto, got, c.want, c.why)
		}
	}

	// --- resolution edge cases ---
	// No ports → any observed port on the resolved IPs matches.
	anyPort := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "kubernetes"}}, l)
	if !Matches(anyPort, clusterIP, 443, "TCP") || !Matches(anyPort, clusterIP, 6443, "TCP") || !Matches(anyPort, endpoint, 8443, "UDP") {
		t.Error("a serviceRef with no ports must match any observed port/proto on its IPs")
	}
	// Unknown Service → nothing (never a match-all).
	if got := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "does-not-exist"}, Ports: tcp(443)}, l); len(got) != 0 {
		t.Errorf("unknown Service must resolve to zero tuples, got %d", len(got))
	}
	// Namespace only, no name → not a resolvable Service.
	if got := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", ""}, Ports: tcp(443)}, l); len(got) != 0 {
		t.Errorf("serviceRef with no name must resolve to zero tuples, got %d", len(got))
	}
	// Wrong namespace for the same name → nothing.
	if got := Resolve(PeerSpec{ServiceRef: &ServiceRef{"kube-system", "kubernetes"}, Ports: tcp(443)}, l); len(got) != 0 {
		t.Errorf("kubernetes Service exists only in default; other namespace must resolve to zero, got %d", len(got))
	}
	// nil lister → nothing.
	if got := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "kubernetes"}, Ports: tcp(443)}, nil); got != nil {
		t.Errorf("nil lister must resolve to nil, got %v", got)
	}
	// Headless Service (no ClusterIP) → resolves to its endpoints only.
	l.services["default/headless"] = &ServiceInfo{Namespace: "default", Name: "headless", EndpointIPs: []string{"10.42.9.9"}}
	hl := Resolve(PeerSpec{ServiceRef: &ServiceRef{"default", "headless"}, Ports: tcp(80)}, l)
	if !Matches(hl, "10.42.9.9", 80, "TCP") {
		t.Error("a headless Service must resolve to its endpoint IPs")
	}
	// DNS names: the Service FQDN is implied.
	dns := ResolveDNSNames(PeerSpec{ServiceRef: &ServiceRef{"default", "kubernetes"}}, l)
	if len(dns) != 1 || dns[0] != "kubernetes.default.svc.cluster.local" {
		t.Errorf("serviceRef must imply the cluster FQDN, got %v", dns)
	}
}

// TestEntityHost_TruthTable is the full matrix for the "host" entity: it
// resolves to the node's InternalIP(s) plus the CNI gateway, and nothing else.
func TestEntityHost_TruthTable(t *testing.T) {
	l := realFluxTopology() // hostIPs: node 192.168.0.191, gateway 10.42.0.1
	const (
		nodeIP  = "192.168.0.191"
		gateway = "10.42.0.1"
	)

	tuples := Resolve(PeerSpec{Entity: EntityHost, Ports: tcp(10250)}, l)
	grid := []struct {
		ip    string
		port  int32
		proto string
		want  bool
		why   string
	}{
		{nodeIP, 10250, "TCP", true, "node InternalIP on the kubelet port"},
		{gateway, 10250, "TCP", true, "CNI gateway (masqueraded node traffic)"},
		{nodeIP, 10250, "tcp", true, "protocol case-insensitive"},
		{nodeIP, 9090, "TCP", false, "wrong port"},
		{nodeIP, 10250, "UDP", false, "wrong protocol"},
		{"10.42.0.55", 10250, "TCP", false, "a pod IP is not a host IP"},
		{"10.43.0.1", 10250, "TCP", false, "a ClusterIP is not a host IP"},
		{"", 10250, "TCP", false, "empty IP never matches"},
	}
	for _, c := range grid {
		if got := Matches(tuples, c.ip, c.port, c.proto); got != c.want {
			t.Errorf("Matches(%q,%d,%s)=%v want %v — %s", c.ip, c.port, c.proto, got, c.want, c.why)
		}
	}

	// --- edge cases ---
	// No ports → any observed port on the host IPs.
	anyPort := Resolve(PeerSpec{Entity: EntityHost}, l)
	if !Matches(anyPort, nodeIP, 22, "TCP") || !Matches(anyPort, gateway, 53, "UDP") {
		t.Error("host entity with no ports must match any observed port on its IPs")
	}
	// "host" is case-insensitive.
	if got := Resolve(PeerSpec{Entity: "HOST", Ports: tcp(10250)}, l); !Matches(got, nodeIP, 10250, "TCP") {
		t.Error("the host entity name must be case-insensitive")
	}
	// An unknown entity resolves to nothing (never a match-all).
	if got := Resolve(PeerSpec{Entity: "world", Ports: tcp(443)}, l); len(got) != 0 {
		t.Errorf("unknown entity must resolve to zero tuples, got %d", len(got))
	}
	// Empty entity string → nothing.
	if got := Resolve(PeerSpec{Entity: "", Ports: tcp(443)}, l); len(got) != 0 {
		t.Errorf("empty entity must resolve to zero tuples, got %d", len(got))
	}
	// host entity implies no DNS name (it is not a Service).
	if got := ResolveDNSNames(PeerSpec{Entity: EntityHost}, l); got != nil {
		t.Errorf("host entity must imply no FQDN, got %v", got)
	}
	// nil lister → nothing.
	if got := Resolve(PeerSpec{Entity: EntityHost}, nil); got != nil {
		t.Errorf("nil lister must resolve to nil, got %v", got)
	}
}
