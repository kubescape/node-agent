package networkpeer

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nsName(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}
}

// TestExpandServiceNeighbors_NamespaceSelectorConsistency proves the service
// (serviceSelector) resolution path scopes namespaces with the SAME three tiers
// as the podSelector matcher — compare row-for-row with
// containerprofilenetwork.TestNamespaceSelectorMatches_TruthTable and
// TestWasSelectorInPeers_NamespaceDisambiguation:
//
//	OMITTED (nil)        => the profile's OWN namespace
//	explicit EMPTY {}    => cluster-wide (opt-in)
//	explicit metadata.name => that namespace
//
// An identical Service {app: api} exists in the profile's namespace ("prod") and
// in "attacker"; profileNs is "prod".
func TestExpandServiceNeighbors_NamespaceSelectorConsistency(t *testing.T) {
	const profileNs = "prod"
	l := &fakeLister{services: map[string]*ServiceInfo{
		"prod/api":     {Namespace: "prod", Name: "api", Labels: map[string]string{"app": "api", "__ns__": "prod"}, ClusterIPs: []string{"10.0.0.1"}},
		"attacker/api": {Namespace: "attacker", Name: "api", Labels: map[string]string{"app": "api", "__ns__": "attacker"}, ClusterIPs: []string{"10.0.0.2"}},
	}}
	svcSel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}

	resolved := func(nsSel *metav1.LabelSelector) map[string]bool {
		n := v1beta1.NetworkNeighbor{Identifier: "api", ServiceSelector: svcSel, NamespaceSelector: nsSel, Ports: []v1beta1.NetworkPort{port("TCP-80", 80)}}
		got := map[string]bool{}
		for _, o := range ExpandServiceNeighbors([]v1beta1.NetworkNeighbor{n}, profileNs, l) {
			for _, ip := range o.IPAddresses {
				got[ip] = true
			}
		}
		return got
	}

	cases := []struct {
		name              string
		nsSel             *metav1.LabelSelector
		wantProd, wantAtk bool
	}{
		{"omitted => same ns (prod only)", nil, true, false},
		{"empty {} => cluster-wide (both)", &metav1.LabelSelector{}, true, true},
		{"metadata.name=prod => prod only", nsName("prod"), true, false},
		{"metadata.name=attacker => attacker only", nsName("attacker"), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolved(tc.nsSel)
			if got["10.0.0.1"] != tc.wantProd || got["10.0.0.2"] != tc.wantAtk {
				t.Fatalf("prod=%v attacker=%v, want prod=%v attacker=%v",
					got["10.0.0.1"], got["10.0.0.2"], tc.wantProd, tc.wantAtk)
			}
		})
	}
}

// TestExpandServiceNeighbors_VendorPortableProfile is the service-path twin of
// containerprofilenetwork.TestWasSelectorInPeers_VendorPortableProfile: a vendor
// ships the SAME serviceSelector peers WITHOUT its namespace, installed anywhere.
// DNS is pinned to kube-system by name; Prometheus uses {} (any ns, the vendor
// can't know monitoring's namespace); the app's own backend uses an omitted
// selector (same ns). A same-labelled backend Service in "evil" is NOT resolved.
func TestExpandServiceNeighbors_VendorPortableProfile(t *testing.T) {
	topo := func(install string) *fakeLister {
		return &fakeLister{services: map[string]*ServiceInfo{
			"kube-system/kube-dns":  {Namespace: "kube-system", Name: "kube-dns", Labels: map[string]string{"k8s-app": "kube-dns", "__ns__": "kube-system"}, ClusterIPs: []string{"10.96.0.10"}},
			"monitoring/prometheus": {Namespace: "monitoring", Name: "prometheus", Labels: map[string]string{"app.kubernetes.io/name": "prometheus", "__ns__": "monitoring"}, ClusterIPs: []string{"10.96.1.1"}},
			install + "/backend":    {Namespace: install, Name: "backend", Labels: map[string]string{"app.kubernetes.io/name": "acme-backend", "__ns__": install}, ClusterIPs: []string{"10.96.2.2"}},
			"evil/backend":          {Namespace: "evil", Name: "backend", Labels: map[string]string{"app.kubernetes.io/name": "acme-backend", "__ns__": "evil"}, ClusterIPs: []string{"10.96.9.9"}},
		}}
	}
	peers := []v1beta1.NetworkNeighbor{
		{Identifier: "dns", ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}}, NamespaceSelector: nsName("kube-system"), Ports: []v1beta1.NetworkPort{port("UDP-53", 53)}},
		{Identifier: "prometheus", ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "prometheus"}}, NamespaceSelector: &metav1.LabelSelector{}, Ports: []v1beta1.NetworkPort{port("TCP-9090", 9090)}},
		{Identifier: "backend", ServiceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "acme-backend"}}, Ports: []v1beta1.NetworkPort{port("TCP-8080", 8080)}},
	}

	for _, install := range []string{"acme", "tenant-42"} {
		t.Run("install="+install, func(t *testing.T) {
			ips := map[string]bool{}
			for _, o := range ExpandServiceNeighbors(peers, install, topo(install)) {
				for _, ip := range o.IPAddresses {
					ips[ip] = true
				}
			}
			if !ips["10.96.0.10"] {
				t.Error("DNS in kube-system must resolve (metadata.name pin)")
			}
			if !ips["10.96.1.1"] {
				t.Error("Prometheus must resolve in monitoring ({} cluster-wide)")
			}
			if !ips["10.96.2.2"] {
				t.Errorf("the app's own backend in the install ns %q must resolve (omitted = same ns)", install)
			}
			if ips["10.96.9.9"] {
				t.Error("LABEL-COPY: a same-labelled backend Service in another ns must NOT resolve")
			}
		})
	}
}
