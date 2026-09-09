package networkpeer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

// Field failure this pins: on two Cilium clusters every kubelet health probe was
// scored as un-allowlisted ingress and the resulting alert stream nearly took a
// node down. The probe is masqueraded to the node's router address, which on
// Cilium is neither the node's InternalIP nor derivable from its podCIDR — the
// observed values below are from that cluster, where the control-plane node's
// router address sits inside a DIFFERENT node's podCIDR, and the address moves
// when the CNI restarts, which is why a literal entry in a profile cannot fix
// this: on the second cluster two otherwise identical profiles differed only in
// which router address they had frozen, and the stale one produced 8,649 alerts
// while the current one produced none.
//
// Fixtures, all real:
//
//	node             InternalIP      podCIDR        router (cilium_host)
//	edge4-server     10.0.104.202    10.42.0.0/24   10.42.2.156
//	edge4-worker-1   10.0.104.107    10.42.1.0/24   10.42.1.121
//	edge4-worker-2   10.0.104.181    10.42.2.0/24   10.42.0.244
const (
	serverInternalIP = "10.0.104.202"
	serverRouterIP   = "10.42.2.156" // not inside 10.42.0.0/24
	worker1RouterIP  = "10.42.1.121"
	worker2RouterIP  = "10.42.0.244"
	unrelatedPodIP   = "10.42.1.50"
)

// fibTrie writes a /proc/net/fib_trie in the kernel's own shape, so the parser
// is tested against the format it will actually meet.
func fibTrie(t *testing.T, localIPs, broadcastIPs []string) string {
	t.Helper()
	body := "Main:\n  +-- 0.0.0.0/0 3 0 4\n     |-- 10.42.0.0\n        /24 universe UNICAST\n" +
		"Local:\n  +-- 0.0.0.0/1 3 0 5\n"
	for _, ip := range localIPs {
		body += "     |-- " + ip + "\n        /32 host LOCAL\n"
	}
	for _, ip := range broadcastIPs {
		body += "     |-- " + ip + "\n        /32 link BROADCAST\n"
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fib_trie"), []byte(body), 0o600))
	return dir
}

// The production path is PID 1's netns view; the tests point it at a fixture.
func withHostProc(t *testing.T, dir string) {
	t.Helper()
	prev := hostProcNetRoot
	hostProcNetRoot = dir
	t.Cleanup(func() { hostProcNetRoot = prev })
}

func listerFor(t *testing.T, node *corev1.Node, nodeName string) *InformerLister {
	t.Helper()
	objects := []runtime.Object{node}
	if node.Name != "edge4-worker-2" {
		// another node, whose addresses must never leak into this one's set
		objects = append(objects, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "edge4-worker-2",
				Annotations: map[string]string{ciliumHostAnnotation: worker2RouterIP}},
			Spec:   corev1.NodeSpec{PodCIDR: "10.42.2.0/24", PodCIDRs: []string{"10.42.2.0/24"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.104.181"}}},
		})
	}
	client := fake.NewSimpleClientset(objects...)
	factory := informers.NewSharedInformerFactory(client, 0)
	l := NewInformerLister(
		factory.Core().V1().Services().Lister(),
		factory.Discovery().V1().EndpointSlices().Lister(),
		factory.Core().V1().Nodes().Lister(),
		nodeName,
	)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	factory.Start(stop)
	factory.WaitForCacheSync(stop)
	return l
}

func serverNode(annotated bool) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "edge4-server"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.42.0.0/24", PodCIDRs: []string{"10.42.0.0/24"}},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: serverInternalIP}}},
	}
	if annotated {
		n.Annotations = map[string]string{ciliumHostAnnotation: serverRouterIP}
	}
	return n
}

// T1: the router address the probe actually comes from is part of the node's
// host peers, however the CNI chose it.
func TestHostIPs_IncludesTheNodesOwnRouterAddress(t *testing.T) {
	withHostProc(t, fibTrie(t,
		[]string{"127.0.0.1", serverInternalIP, serverRouterIP},
		[]string{"10.42.0.255"}))
	l := listerFor(t, serverNode(false), "edge4-server")

	ips := l.HostIPs()
	assert.Contains(t, ips, serverRouterIP,
		"the probe source is a local address of the node, so it must be a host peer even though it is outside this node's podCIDR")
	assert.Contains(t, ips, serverInternalIP)
	assert.NotContains(t, ips, "127.0.0.1", "loopback is never a peer")
	assert.NotContains(t, ips, "10.42.0.255", "a broadcast address is never a peer")
}

// T1 again, on a cluster whose CNI publishes the address on the Node object
// instead: the same outcome without reading the host at all.
func TestHostIPs_UsesTheNodeAnnotationWhenTheHostIsUnreadable(t *testing.T) {
	withHostProc(t, t.TempDir()) // no fib_trie
	l := listerFor(t, serverNode(true), "edge4-server")
	assert.Contains(t, l.HostIPs(), serverRouterIP,
		"a published router address is enough on its own")
}

// T3, the negative that the local-node scope preserves: another node's router
// address is NOT a host peer here, so node-sourced traffic arriving across
// nodes keeps alerting.
func TestHostIPs_ExcludesOtherNodesAndOrdinaryPods(t *testing.T) {
	withHostProc(t, fibTrie(t, []string{serverInternalIP, serverRouterIP}, nil))
	l := listerFor(t, serverNode(true), "edge4-server")

	ips := l.HostIPs()
	assert.NotContains(t, ips, worker2RouterIP,
		"another node's router address must keep alerting: that is cross-node node-sourced traffic, not a local probe")
	assert.NotContains(t, ips, worker1RouterIP)
	assert.NotContains(t, ips, "10.0.104.181", "another node's InternalIP is not this node's host peer")
	assert.NotContains(t, ips, unrelatedPodIP, "an ordinary pod address is never a host peer")

	// The whole pod network must not be swept in: only named addresses.
	for _, ip := range ips {
		assert.NotEqual(t, "10.42.0.0/16", ip, "host peers are addresses, never ranges")
	}
}

// The gateway-derivation path must keep working. On a CNI that puts the router
// address at the pod-CIDR gateway this is the whole mechanism, and it is the
// only one that survives losing host access, so a fix aimed at one CNI must not
// remove it. Exercised for real on a two-node cluster whose probes source from
// that gateway.
func TestHostIPs_PodCIDRGatewayStillResolves(t *testing.T) {
	withHostProc(t, fibTrie(t, []string{"10.0.104.202", "10.42.0.1", "10.42.0.0"}, nil))
	l := listerFor(t, serverNode(false), "edge4-server")

	ips := l.HostIPs()
	assert.Contains(t, ips, "10.42.0.1", "the pod-CIDR gateway is where such a probe comes from")
	assert.Contains(t, ips, "10.42.0.0", "the overlay interface address is local too")

	// And with no host access at all, the gateway derivation alone still holds.
	withHostProc(t, t.TempDir())
	bare := listerFor(t, serverNode(false), "edge4-server")
	assert.Contains(t, bare.HostIPs(), "10.42.0.1",
		"losing host access must not lose the case that already worked")
}

// T2: a pod moved to another node is evaluated by that node's agent, which
// reads its own addresses. There is no cluster-wide set to keep in step.
func TestHostIPs_AreResolvedPerNode(t *testing.T) {
	withHostProc(t, fibTrie(t, []string{"10.0.104.181", worker2RouterIP}, nil))
	moved := listerFor(t, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "edge4-worker-2"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.42.2.0/24"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.104.181"}}},
	}, "edge4-worker-2")

	ips := moved.HostIPs()
	assert.Contains(t, ips, worker2RouterIP, "the new node's own router address is what its probes now come from")
	assert.NotContains(t, ips, serverRouterIP, "and the old node's is not")
}

// A changed address set must reach profiles that were already projected, or the
// probe keeps alerting until something else happens to re-project them.
func TestLocalAddrs_ChangeBumpsTheGeneration(t *testing.T) {
	l := &InformerLister{}
	set := []string{serverRouterIP}
	l.readLocalAddrs = func() []string { return set }

	first := l.localAddrs()
	assert.Equal(t, []string{serverRouterIP}, first)
	genAfterFirst := l.Generation()

	// Same set, read again after the cache expires: no churn.
	l.localReadAt = l.localReadAt.Add(-2 * localAddrTTL)
	l.localAddrs()
	assert.Equal(t, genAfterFirst, l.Generation(), "an unchanged set must not force re-projection")

	// A new interface appears.
	set = []string{serverRouterIP, "10.42.5.1"}
	l.localReadAt = l.localReadAt.Add(-2 * localAddrTTL)
	l.localAddrs()
	assert.Greater(t, l.Generation(), genAfterFirst, "a changed set must re-project the profiles that used the old one")
}
