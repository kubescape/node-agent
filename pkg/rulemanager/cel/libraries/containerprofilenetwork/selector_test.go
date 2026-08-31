package containerprofilenetwork

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func podSel(m map[string]string) *metav1.LabelSelector { return &metav1.LabelSelector{MatchLabels: m} }
func nsSel(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}
}

// TestWasSelectorInPeers_TruthTable is the full matrix for peer-selector
// matching under NetworkPolicy semantics: matching is on pod LABELS; an OMITTED
// (nil) namespaceSelector means the profile's OWN namespace; an explicit empty
// {} is cluster-wide; an explicit metadata.name selector pins a namespace; an
// empty podSelector matches NOTHING (fail closed, opposite of NetworkPolicy).
// profileNs is the namespace the profiled workload runs in ("redis" here).
func TestWasSelectorInPeers_TruthTable(t *testing.T) {
	const profileNs = "redis"
	client := labels.Set{"app": "redis-client"}
	clientPlus := labels.Set{"app": "redis-client", "tier": "cache"}

	exprIn := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"redis-client"}}}}
	exprExists := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpExists}}}

	p := func(pod, ns *metav1.LabelSelector) objectcache.PeerSelector {
		return objectcache.PeerSelector{PodSelector: pod, NamespaceSelector: ns}
	}

	cases := []struct {
		name   string
		peers  []objectcache.PeerSelector
		labels labels.Set
		peerNs string
		want   bool
	}{
		// --- podSelector shapes ---
		{"nil podSelector never matches", []objectcache.PeerSelector{p(nil, nil)}, client, "redis", false},
		{"empty podSelector matches nothing (same ns)", []objectcache.PeerSelector{p(podSel(map[string]string{}), nil)}, client, "redis", false},
		{"empty podSelector matches nothing (empty labels)", []objectcache.PeerSelector{p(podSel(map[string]string{}), nil)}, labels.Set{}, "redis", false},
		{"empty podSelector matches nothing (explicit ns)", []objectcache.PeerSelector{p(podSel(map[string]string{}), nsSel("redis"))}, client, "redis", false},

		// --- omitted (nil) namespaceSelector => SAME namespace as the profile ---
		{"label match, omitted ns, same ns", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, client, "redis", true},
		{"label match, omitted ns, FOREIGN ns REJECTED (same-ns default)", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, client, "attacker", false},
		{"label mismatch, omitted ns", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, labels.Set{"app": "other"}, "redis", false},
		{"selector is a subset of pod labels", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, clientPlus, "redis", true},
		{"non-empty selector vs empty labels", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, labels.Set{}, "redis", false},

		// --- explicit metadata.name namespaceSelector (named namespace) ---
		{"label+ns match", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("redis"))}, client, "redis", true},
		{"explicit ns mismatch rejects (same labels)", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("redis"))}, client, "attacker", false},
		{"explicit ns names a third namespace", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("other"))}, client, "redis", false},

		// --- explicit EMPTY {} namespaceSelector => cluster-wide (opt-in) ---
		{"empty {} ns selector matches any ns (same)", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), &metav1.LabelSelector{})}, client, "redis", true},
		{"empty {} ns selector matches any ns (foreign)", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), &metav1.LabelSelector{})}, client, "attacker", true},

		// --- matchExpressions (omitted ns => same ns) ---
		{"matchExpressions In matches", []objectcache.PeerSelector{p(exprIn, nil)}, client, "redis", true},
		{"matchExpressions Exists matches labelled pod", []objectcache.PeerSelector{p(exprExists, nil)}, client, "redis", true},
		{"matchExpressions Exists rejects unlabelled pod", []objectcache.PeerSelector{p(exprExists, nil)}, labels.Set{}, "redis", false},

		// --- list semantics ---
		{"empty peer list", nil, client, "redis", false},
		{"one of several matches", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "x"}), nil), p(podSel(map[string]string{"app": "redis-client"}), nil)}, client, "redis", true},
		{"none of several matches", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "x"}), nil), p(podSel(map[string]string{"app": "y"}), nil)}, client, "redis", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSelectorInPeers(tc.peers, tc.labels, tc.peerNs, profileNs, "TCP", 443); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNamespaceSelectorMatches_TruthTable pins the three namespaceSelector tiers:
// omitted (nil) = the profile's own namespace; explicit metadata.name = a named
// namespace (profileNs ignored); explicit empty {} = cluster-wide.
func TestNamespaceSelectorMatches_TruthTable(t *testing.T) {
	cases := []struct {
		name      string
		sel       *metav1.LabelSelector
		peerNs    string
		profileNs string
		want      bool
	}{
		{"omitted matches same ns", nil, "prod", "prod", true},
		{"omitted rejects foreign ns (same-ns default)", nil, "attacker", "prod", false},
		{"explicit metadata.name matches (profileNs ignored)", nsSel("prod"), "prod", "other", true},
		{"explicit metadata.name rejects other", nsSel("prod"), "attacker", "prod", false},
		{"empty {} is cluster-wide", &metav1.LabelSelector{}, "anywhere", "prod", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := namespaceSelectorMatches(tc.sel, tc.peerNs, tc.profileNs); got != tc.want {
				t.Fatalf("namespaceSelectorMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWasSelectorInPeers_InvalidSelectorFailsClosed(t *testing.T) {
	const profileNs = "redis"
	client := labels.Set{"app": "redis-client"}
	badPod := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpIn}}}
	badNs := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "kubernetes.io/metadata.name", Operator: "BadOp", Values: []string{"redis"}}}}
	good := podSel(map[string]string{"app": "redis-client"})

	cases := []struct {
		name  string
		peers []objectcache.PeerSelector
		want  bool
		why   string
	}{
		{"invalid podSelector alone", []objectcache.PeerSelector{{PodSelector: badPod}}, false, "unparseable podSelector must never match"},
		{"invalid podSelector skipped, later valid peer matches", []objectcache.PeerSelector{{PodSelector: badPod}, {PodSelector: good}}, true, "one bad entry must not poison the list"},
		{"valid podSelector, invalid namespaceSelector", []objectcache.PeerSelector{{PodSelector: good, NamespaceSelector: badNs}}, false, "unparseable namespaceSelector fails closed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSelectorInPeers(tc.peers, client, "redis", profileNs, "TCP", 443); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestNamespaceSelectorMatches_InvalidSelectorFailsClosed(t *testing.T) {
	bad := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpIn}}}
	if namespaceSelectorMatches(bad, "redis", "redis") {
		t.Fatal("an unparseable namespaceSelector must fail closed, not match")
	}
}

// A selector peer with a Ports set is port-aware, mirroring the address matcher:
// nil Ports means any port, a declared (proto,port) matches only itself, and an
// empty-but-non-nil map matches nothing. Peers are same-namespace (omitted ns).
func TestWasSelectorInPeers_PortAware(t *testing.T) {
	const profileNs = "redis"
	sel := podSel(map[string]string{"app": "redis-client"})
	client := labels.Set{"app": "redis-client"}
	withPorts := func(keys ...string) objectcache.PeerSelector {
		m := map[string]struct{}{}
		for _, k := range keys {
			m[k] = struct{}{}
		}
		return objectcache.PeerSelector{PodSelector: sel, Ports: m}
	}
	k6379 := objectcache.PortKey("TCP", 6379)
	cases := []struct {
		name  string
		peers []objectcache.PeerSelector
		proto string
		port  int32
		want  bool
	}{
		{"nil ports matches any port", []objectcache.PeerSelector{{PodSelector: sel}}, "TCP", 6379, true},
		{"declared port matches", []objectcache.PeerSelector{withPorts(k6379)}, "TCP", 6379, true},
		{"undeclared port rejected", []objectcache.PeerSelector{withPorts(k6379)}, "TCP", 5432, false},
		{"wrong protocol rejected", []objectcache.PeerSelector{withPorts(k6379)}, "UDP", 6379, false},
		{"empty ports map matches nothing", []objectcache.PeerSelector{{PodSelector: sel, Ports: map[string]struct{}{}}}, "TCP", 6379, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSelectorInPeers(tc.peers, client, "redis", profileNs, tc.proto, tc.port); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWasSelectorInPeers_NamespaceDisambiguation states the collision case: two
// pods carry IDENTICAL podSelector labels in different namespaces. Omitted ns
// matches only the profile's own namespace (rejecting a label-copy elsewhere);
// explicit {} is cluster-wide; explicit metadata.name pins one namespace.
func TestWasSelectorInPeers_NamespaceDisambiguation(t *testing.T) {
	const profileNs = "prod"
	sameLabels := labels.Set{"app": "frontend"}
	frontend := podSel(map[string]string{"app": "frontend"})

	omitted := []objectcache.PeerSelector{{PodSelector: frontend}}
	if !wasSelectorInPeers(omitted, sameLabels, "prod", profileNs, "TCP", 443) {
		t.Fatal("omitted ns: frontend in the profile's own namespace must match")
	}
	if wasSelectorInPeers(omitted, sameLabels, "attacker", profileNs, "TCP", 443) {
		t.Fatal("LABEL-COPY: omitted ns must reject the same-labelled pod in another namespace")
	}

	clusterWide := []objectcache.PeerSelector{{PodSelector: frontend, NamespaceSelector: &metav1.LabelSelector{}}}
	if !wasSelectorInPeers(clusterWide, sameLabels, "prod", profileNs, "TCP", 443) ||
		!wasSelectorInPeers(clusterWide, sameLabels, "attacker", profileNs, "TCP", 443) {
		t.Fatal("empty {} ns selector must match in ANY namespace (cluster-wide opt-in)")
	}

	pinned := []objectcache.PeerSelector{{PodSelector: frontend, NamespaceSelector: nsSel("prod")}}
	if !wasSelectorInPeers(pinned, sameLabels, "prod", profileNs, "TCP", 443) {
		t.Fatal("pinned ns=prod: frontend in prod must match")
	}
	if wasSelectorInPeers(pinned, sameLabels, "attacker", profileNs, "TCP", 443) {
		t.Fatal("pinned ns=prod: identical-labelled frontend elsewhere must be rejected")
	}
}

// TestWasSelectorInPeers_VendorPortableProfile is the real-world story: a vendor
// ships a signed ContainerProfile WITHOUT its own namespace (the customer installs
// the workload into a namespace the vendor cannot know at signing time). The SAME
// peer bytes must work in any install namespace. The three tiers cover it:
//   - DNS      -> namespaceSelector metadata.name=kube-system   (a universal name)
//   - Prometheus/Alertmanager -> namespaceSelector {}           (any ns; vendor can't know it)
//   - own frontend            -> omitted namespaceSelector      (same ns as the install)
//
// It also proves the label-copy defense: an attacker's acme-frontend in another
// namespace does NOT inherit the same-namespace peer's trust.
func TestWasSelectorInPeers_VendorPortableProfile(t *testing.T) {
	dns := objectcache.PeerSelector{
		PodSelector:       podSel(map[string]string{"k8s-app": "kube-dns"}),
		NamespaceSelector: nsSel("kube-system"),
	}
	prometheus := objectcache.PeerSelector{
		PodSelector:       podSel(map[string]string{"app.kubernetes.io/name": "prometheus"}),
		NamespaceSelector: &metav1.LabelSelector{},
	}
	alertmanager := objectcache.PeerSelector{
		PodSelector:       podSel(map[string]string{"app.kubernetes.io/name": "alertmanager"}),
		NamespaceSelector: &metav1.LabelSelector{},
	}
	frontend := objectcache.PeerSelector{
		PodSelector: podSel(map[string]string{"app.kubernetes.io/name": "acme-frontend"}),
	}
	peers := []objectcache.PeerSelector{dns, prometheus, alertmanager, frontend}

	dnsPod := labels.Set{"k8s-app": "kube-dns"}
	promPod := labels.Set{"app.kubernetes.io/name": "prometheus"}
	amPod := labels.Set{"app.kubernetes.io/name": "alertmanager"}
	frontPod := labels.Set{"app.kubernetes.io/name": "acme-frontend"}

	for _, install := range []string{"acme", "tenant-42"} {
		t.Run("install="+install, func(t *testing.T) {
			match := func(pod labels.Set, peerNs string) bool {
				return wasSelectorInPeers(peers, pod, peerNs, install, "TCP", 9090)
			}
			if !match(dnsPod, "kube-system") {
				t.Fatal("DNS: kube-dns in kube-system must match")
			}
			if match(dnsPod, install) {
				t.Fatal("DNS: a kube-dns pod in the install namespace must NOT match the kube-system-pinned peer")
			}
			if !match(promPod, "monitoring") || !match(promPod, "observability") {
				t.Fatal("Prometheus: {} must match prometheus in ANY namespace")
			}
			if !match(amPod, "monitoring") {
				t.Fatal("Alertmanager: {} must match alertmanager in the monitoring namespace")
			}
			if !match(frontPod, install) {
				t.Fatalf("frontend: acme-frontend in the install ns %q must match (omitted = same ns)", install)
			}
			if match(frontPod, "evil") {
				t.Fatal("LABEL-COPY: acme-frontend in another namespace must NOT match the same-namespace peer")
			}
		})
	}
}
