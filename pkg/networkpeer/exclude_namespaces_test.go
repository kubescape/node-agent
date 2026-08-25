package networkpeer

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
)

// excludeNamespaces (Config.SkipNamespace) filters which WORKLOADS node-agent
// profiles; the selector resolver queries a cluster-wide Service/Node view that
// is unaware of it. These pin the resulting asymmetry so it is deliberate.
func excludedTopology() *fakeLister {
	l := realFluxTopology()
	l.services["kube-system/kube-dns"] = &ServiceInfo{
		Namespace: "kube-system", Name: "kube-dns",
		Labels:      map[string]string{"k8s-app": "kube-dns", "probe": "yes", "__ns__": "kube-system"},
		ClusterIPs:  []string{"10.43.0.10"},
		EndpointIPs: []string{"10.42.0.5"},
	}
	l.services["honey/storage"].Labels["probe"] = "yes"
	return l
}

func TestExcludeNamespaces_ServiceRefIntoExcludedNsStillResolves(t *testing.T) {
	cfg := &config.Config{ExcludeNamespaces: []string{"kube-system"}}
	if !cfg.SkipNamespace("kube-system") {
		t.Fatal("precondition: kube-system must be an excluded namespace")
	}
	l := excludedTopology()
	tuples := Resolve(PeerSpec{ServiceRef: &ServiceRef{"kube-system", "kube-dns"}, Ports: tcp(53)}, l)
	for _, ip := range []string{"10.43.0.10", "10.42.0.5"} {
		if !Matches(tuples, ip, 53, "TCP") {
			t.Errorf("serviceRef naming excluded ns %s:53 must still resolve — excludeNamespaces does not gate peer allowlisting", ip)
		}
	}
	if got := ResolveDNSNames(PeerSpec{ServiceRef: &ServiceRef{"kube-system", "kube-dns"}}, l); len(got) != 1 || got[0] != "kube-dns.kube-system.svc.cluster.local" {
		t.Errorf("the excluded-ns Service FQDN is implied too: got %v", got)
	}
}

func TestExcludeNamespaces_ServiceSelectorFansIntoExcludedNs(t *testing.T) {
	cfg := &config.Config{ExcludeNamespaces: []string{"kube-system"}}
	l := excludedTopology()

	all := Resolve(PeerSpec{ServiceSelector: map[string]string{"probe": "yes"}, Ports: tcp(53)}, l)
	if !Matches(all, "10.43.0.10", 53, "TCP") {
		t.Error("a namespace-less serviceSelector fans into the excluded namespace (kube-dns) — exclusion does not scope fanout")
	}
	if !Matches(all, "10.43.70.156", 53, "TCP") {
		t.Error("the same selector still resolves the monitored-ns Service (honey/storage)")
	}
	if !cfg.SkipNamespace("kube-system") {
		t.Fatal("kube-system is excluded, yet its Service was just allowlisted above — the asymmetry under test")
	}

	scoped := Resolve(PeerSpec{
		ServiceSelector: map[string]string{"probe": "yes"},
		NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "honey"},
		Ports:           tcp(53),
	}, l)
	if Matches(scoped, "10.43.0.10", 53, "TCP") {
		t.Error("NamespaceLabels pinned to honey must exclude the kube-system Service")
	}
	if !Matches(scoped, "10.43.70.156", 53, "TCP") {
		t.Error("NamespaceLabels pinned to honey must still resolve honey/storage")
	}
}

// The only namespace-scoping the selectors offer is authored NamespaceLabels;
// the chart's excludeNamespaces is orthogonal to it. This grids the two axes so
// a reader sees excludeNamespaces never appears as an input to resolution.
func TestExcludeNamespaces_TruthTable(t *testing.T) {
	l := excludedTopology()
	const (
		excludedIP = "10.43.0.10"   // kube-system/kube-dns ClusterIP
		monitorIP  = "10.43.70.156" // honey/storage ClusterIP
	)
	cases := []struct {
		name              string
		spec              PeerSpec
		wantExcludedPeer  bool
		wantMonitoredPeer bool
		why               string
	}{
		{
			"serviceRef-excluded-ns",
			PeerSpec{ServiceRef: &ServiceRef{"kube-system", "kube-dns"}, Ports: tcp(53)},
			true, false, "explicit serviceRef into an excluded ns resolves",
		},
		{
			"serviceRef-monitored-ns",
			PeerSpec{ServiceRef: &ServiceRef{"honey", "storage"}, Ports: tcp(53)},
			false, true, "serviceRef into a monitored ns resolves",
		},
		{
			"selector-no-nsLabels",
			PeerSpec{ServiceSelector: map[string]string{"probe": "yes"}, Ports: tcp(53)},
			true, true, "unscoped selector fans across the exclusion boundary",
		},
		{
			"selector-nsLabels-honey",
			PeerSpec{ServiceSelector: map[string]string{"probe": "yes"}, NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "honey"}, Ports: tcp(53)},
			false, true, "NamespaceLabels is the ONLY thing that scopes fanout",
		},
		{
			"selector-nsLabels-kube-system",
			PeerSpec{ServiceSelector: map[string]string{"probe": "yes"}, NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}, Ports: tcp(53)},
			true, false, "NamespaceLabels can deliberately TARGET an excluded ns",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tuples := Resolve(c.spec, l)
			if got := Matches(tuples, excludedIP, 53, "TCP"); got != c.wantExcludedPeer {
				t.Errorf("excluded-ns peer match=%v want %v — %s", got, c.wantExcludedPeer, c.why)
			}
			if got := Matches(tuples, monitorIP, 53, "TCP"); got != c.wantMonitoredPeer {
				t.Errorf("monitored-ns peer match=%v want %v — %s", got, c.wantMonitoredPeer, c.why)
			}
		})
	}
}

// The source/peer asymmetry, stated as one assertion pair under both the
// exclude-denylist and the include-allowlist forms of SkipNamespace.
func TestExcludeNamespaces_SourceSuppressedButPeerAllowlisted(t *testing.T) {
	l := excludedTopology()
	peerResolves := func() bool {
		return Matches(Resolve(PeerSpec{ServiceRef: &ServiceRef{"kube-system", "kube-dns"}, Ports: tcp(53)}, l), "10.43.0.10", 53, "TCP")
	}
	for _, cfg := range []*config.Config{
		{ExcludeNamespaces: []string{"kube-system"}},
		{IncludeNamespaces: []string{"honey"}}, // allowlist form: kube-system is implicitly skipped
	} {
		if !cfg.SkipNamespace("kube-system") {
			t.Fatal("a kube-system SOURCE workload must be skipped from profiling")
		}
		if !peerResolves() {
			t.Error("yet a kube-system PEER remains resolvable/allowlistable — the resolver takes no namespace-exclusion input")
		}
	}
}

// The host entity has no namespace, so excludeNamespaces cannot touch it.
func TestExcludeNamespaces_HostEntityOrthogonal(t *testing.T) {
	l := excludedTopology()
	tuples := Resolve(PeerSpec{Entity: EntityHost, Ports: tcp(10250)}, l)
	if !Matches(tuples, "192.168.0.191", 10250, "TCP") {
		t.Error("host entity resolves regardless of any excludeNamespaces setting (it names no namespace)")
	}
}
