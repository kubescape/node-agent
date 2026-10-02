package tracers

import (
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/stretchr/testify/require"
)

func slim(ns, name, ip string, host bool, labels map[string]string) *common.SlimPod {
	p := &common.SlimPod{}
	p.Namespace, p.Name, p.Labels = ns, name, labels
	p.Status.PodIP = ip
	p.Spec.HostNetwork = host
	return p
}

func TestPeerRepair_ReusedAddressResolvesToTheCurrentPod(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pods := []*common.SlimPod{
		slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api", "pod-template-hash": "cc49b4b9f"}),
		slim("kube-system", "kube-proxy-x", "172.16.0.3", true, map[string]string{"k8s-app": "kube-proxy"}),
	}
	calls := 0
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: func() time.Time { return now }, pods: func() []*common.SlimPod { calls++; return pods }}

	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "shop", id.namespace)
	require.Equal(t, "api-new", id.name)
	require.Equal(t, "app=api,pod-template-hash=cc49b4b9f", id.labels)

	_, ok = r.lookup("172.16.0.3")
	require.False(t, ok, "host-network pods are not peers by address")

	_, ok = r.lookup("10.42.9.9")
	require.False(t, ok)
	require.Equal(t, 3, calls)
	_, _ = r.lookup("10.42.0.48")
	_, _ = r.lookup("10.42.9.9")
	require.Equal(t, 3, calls, "hits and misses are both cached")

	now = now.Add(peerMissTTL + time.Second)
	pods = append(pods, slim("shop", "late", "10.42.9.9", false, map[string]string{"app": "late"}))
	id, ok = r.lookup("10.42.9.9")
	require.True(t, ok, "a miss is retried after its short TTL and finds the pod that appeared")
	require.Equal(t, "late", id.name)

	now = now.Add(peerHitTTL + time.Second)
	pods[0] = slim("shop", "api-newer", "10.42.0.48", false, map[string]string{"app": "api"})
	id, _ = r.lookup("10.42.0.48")
	require.Equal(t, "api-newer", id.name, "a hit is re-resolved after its TTL, so an address handed to another pod follows it")
}

func TestPodByIP_FirstNonHostMatch(t *testing.T) {
	pods := []*common.SlimPod{
		nil,
		slim("a", "hostnet", "10.0.0.1", true, nil),
		slim("a", "real", "10.0.0.1", false, nil),
	}
	require.Equal(t, "real", podByIP(pods, "10.0.0.1").Name)
	require.Nil(t, podByIP(pods, "10.0.0.2"))
	require.Equal(t, "", labelString(nil))
}
