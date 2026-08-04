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
	nsRedis := map[string]string{"kubernetes.io/metadata.name": "redis"}

	cases := []struct {
		name  string
		peers []objectcache.PeerSelector
		want  bool
	}{
		{"label+ns match", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, nsRedis)}, true},
		{"label mismatch", []objectcache.PeerSelector{peer(map[string]string{"app": "other"}, nsRedis)}, false},
		{"ns mismatch", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, map[string]string{"kubernetes.io/metadata.name": "other"})}, false},
		{"nil ns selector matches any ns", []objectcache.PeerSelector{peer(map[string]string{"app": "redis-client"}, nil)}, true},
		{"empty peers", nil, false},
		{"one of several matches", []objectcache.PeerSelector{peer(map[string]string{"app": "x"}, nil), peer(map[string]string{"app": "redis-client"}, nil)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSelectorInPeers(tc.peers, podLabels, ns); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}
