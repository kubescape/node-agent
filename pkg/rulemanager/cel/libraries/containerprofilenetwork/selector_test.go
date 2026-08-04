package containerprofilenetwork

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func peer(pod, ns map[string]string) objectcache.PeerSelector {
	p := objectcache.PeerSelector{PodSelector: &metav1.LabelSelector{MatchLabels: pod}}
	if ns != nil {
		p.NamespaceSelector = &metav1.LabelSelector{MatchLabels: ns}
	}
	return p
}

func TestWasSelectorInPeers(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "redis",
		Labels:    map[string]string{"app": "redis-client"},
	}}
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
			if got := wasSelectorInPeers(tc.peers, pod); got != tc.want {
				t.Fatalf("wasSelectorInPeers = %v, want %v", got, tc.want)
			}
		})
	}
}
