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
// matching. Rules: matching is on pod LABELS; a nil namespaceSelector does NOT
// consult the namespace (it is a collision-disambiguator only); an empty
// podSelector matches NOTHING (fail closed, opposite of NetworkPolicy); an
// explicit namespaceSelector must match; a peer with no resolvable pod identity
// never matches (enforced one layer up in wasSelectorIn, tested there).
func TestWasSelectorInPeers_TruthTable(t *testing.T) {
	client := labels.Set{"app": "redis-client"}
	clientPlus := labels.Set{"app": "redis-client", "tier": "cache"}

	// matchExpressions-based selectors (a non-empty selector expressed without matchLabels).
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

		// --- label matching, nil namespaceSelector (namespace NOT consulted) ---
		{"label match, nil ns, same ns", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, client, "redis", true},
		{"label match, nil ns, FOREIGN ns still matches", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, client, "attacker", true},
		{"label mismatch, nil ns", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, labels.Set{"app": "other"}, "redis", false},
		{"selector is a subset of pod labels", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, clientPlus, "redis", true},
		{"non-empty selector vs empty labels", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nil)}, labels.Set{}, "redis", false},

		// --- explicit namespaceSelector (must match) ---
		{"label+ns match", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("redis"))}, client, "redis", true},
		{"explicit ns mismatch rejects (same labels)", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("redis"))}, client, "attacker", false},
		{"explicit ns names a third namespace", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), nsSel("other"))}, client, "redis", false},
		{"empty (non-nil) ns selector matches any ns", []objectcache.PeerSelector{p(podSel(map[string]string{"app": "redis-client"}), &metav1.LabelSelector{})}, client, "attacker", true},

		// --- matchExpressions ---
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
			if got := wasSelectorInPeers(tc.peers, tc.labels, tc.peerNs, "TCP", 443); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNamespaceSelectorMatches_TruthTable pins the namespace-disambiguator
// alone: nil never consults the namespace, an explicit selector must match by
// the kubernetes.io/metadata.name label.
func TestNamespaceSelectorMatches_TruthTable(t *testing.T) {
	cases := []struct {
		name string
		sel  *metav1.LabelSelector
		ns   string
		want bool
	}{
		{"nil matches same ns", nil, "redis", true},
		{"nil matches foreign ns (not consulted)", nil, "attacker", true},
		{"nil matches empty ns", nil, "", true},
		{"explicit matches", nsSel("redis"), "redis", true},
		{"explicit rejects other", nsSel("redis"), "attacker", false},
		{"empty explicit matches any", &metav1.LabelSelector{}, "attacker", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := namespaceSelectorMatches(tc.sel, tc.ns); got != tc.want {
				t.Fatalf("namespaceSelectorMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWasSelectorInPeers_InvalidSelectorFailsClosed(t *testing.T) {
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
			if got := wasSelectorInPeers(tc.peers, client, "redis", "TCP", 443); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestNamespaceSelectorMatches_InvalidSelectorFailsClosed(t *testing.T) {
	bad := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpIn}}}
	if namespaceSelectorMatches(bad, "redis") {
		t.Fatal("an unparseable namespaceSelector must fail closed, not match")
	}
}

// A selector peer with a Ports set is port-aware, mirroring the address matcher:
// nil Ports means any port, a declared (proto,port) matches only itself, and an
// empty-but-non-nil map matches nothing.
func TestWasSelectorInPeers_PortAware(t *testing.T) {
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
			if got := wasSelectorInPeers(tc.peers, client, "redis", tc.proto, tc.port); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWasSelectorInPeers_NamespaceDisambiguation is the collision case stated
// outright: two pods carry the IDENTICAL podSelector labels in different
// namespaces. A nil namespaceSelector matches both (cluster-wide identity); an
// explicit namespaceSelector pinned to metadata.name matches only the pod in
// that namespace, disambiguating the same-labelled pod elsewhere. This is the
// only runtime scoping against a label-copy in a namespace the peer does not own.
func TestWasSelectorInPeers_NamespaceDisambiguation(t *testing.T) {
	sameLabels := labels.Set{"app": "frontend"}
	frontend := podSel(map[string]string{"app": "frontend"})

	nilPeer := []objectcache.PeerSelector{{PodSelector: frontend}}
	if !wasSelectorInPeers(nilPeer, sameLabels, "prod", "TCP", 443) {
		t.Fatal("nil ns: frontend in prod must match")
	}
	if !wasSelectorInPeers(nilPeer, sameLabels, "attacker", "TCP", 443) {
		t.Fatal("nil ns: identical-labelled frontend in another ns ALSO matches (cluster-wide)")
	}

	pinned := []objectcache.PeerSelector{{PodSelector: frontend, NamespaceSelector: nsSel("prod")}}
	if !wasSelectorInPeers(pinned, sameLabels, "prod", "TCP", 443) {
		t.Fatal("pinned ns=prod: frontend in prod must match")
	}
	if wasSelectorInPeers(pinned, sameLabels, "attacker", "TCP", 443) {
		t.Fatal("pinned ns=prod: identical-labelled frontend in another ns MUST be rejected (disambiguation)")
	}
}
