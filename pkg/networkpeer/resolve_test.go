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
