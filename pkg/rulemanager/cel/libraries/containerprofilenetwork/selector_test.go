package containerprofilenetwork

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func peer(pod, ns map[string]string) objectcache.PeerSelector {
	p := objectcache.PeerSelector{PodSelector: &metav1.LabelSelector{MatchLabels: pod}}
	if ns != nil {
		p.NamespaceSelector = &metav1.LabelSelector{MatchLabels: ns}
	}
	return p
}

func TestWasSelectorInPeers(t *testing.T) {
	// Peer identity as IG's kubeipresolver stamps it onto the event: a namespace
	// and pod labels, resolved cluster-wide. No IP, no local pod lookup.
	podLabels := labels.Set{"app": "redis-client"}
	ns := "redis"
	profileNs := "redis"
	nsRedis := map[string]string{"kubernetes.io/metadata.name": "redis"}

	cases := []struct {
		name   string
		peers  []objectcache.PeerSelector
		peerNs string
		want   bool
	}{
		{"label+ns match", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, nsRedis)}, ns, true},
		{"label mismatch", []objectcache.PeerSelector{peer(map[string]string{"app": "other"}, nsRedis)}, ns, false},
		{"ns mismatch", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, map[string]string{"kubernetes.io/metadata.name": "other"})}, ns, false},
		{"nil ns selector matches the profile namespace", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, nil)}, ns, true},
		{"nil ns selector rejects a foreign namespace", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, nil)}, "attacker", false},
		{"empty peers", nil, ns, false},
		{"one of several matches", []objectcache.PeerSelector{peer(map[string]string{"app": "x"}, nil), peer(map[string]string{"app": "redis-client"}, nil)}, ns, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSelectorInPeers(tc.peers, podLabels, tc.peerNs, profileNs); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWasSelectorInPeers_EmptySelectorAndEmptyLabels(t *testing.T) {
	profileNs := "redis"
	emptySelector := []objectcache.PeerSelector{{PodSelector: &metav1.LabelSelector{}}}

	if !wasSelectorInPeers(emptySelector, labels.Set{}, "redis", profileNs) {
		t.Fatal("an empty podSelector must match a resolved label-less pod in the profile namespace (NetworkPolicyPeer semantics)")
	}
	if wasSelectorInPeers(emptySelector, labels.Set{}, "attacker", profileNs) {
		t.Fatal("an empty podSelector with nil namespaceSelector must not match a pod outside the profile namespace")
	}
	if !wasSelectorInPeers(emptySelector, labels.Set{"app": "anything"}, "redis", profileNs) {
		t.Fatal("an empty podSelector selects all pods in the namespace, labelled or not")
	}
}
