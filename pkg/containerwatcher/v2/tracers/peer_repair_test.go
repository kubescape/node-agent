package tracers

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
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

func TestPeerRepair_OwnershipValidationOnRapidChurn(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pods := []*common.SlimPod{
		slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api", "version": "v1"}),
	}
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: func() time.Time { return now }, pods: func() []*common.SlimPod { return pods }}

	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-old", id.name)

	// Rapid churn happens 2 seconds later (well within the 30s peerHitTTL)
	now = now.Add(2 * time.Second)
	pods[0] = slim("shop", "api-newer", "10.42.0.48", false, map[string]string{"app": "api", "version": "v2"})

	// Plain lookup without expected pod would still hit cache if unvalidated
	// But lookupWithExpected validates that the cached hit matches the expected identity from upstream
	id, ok = r.lookupWithExpected("10.42.0.48", "shop", "api-newer")
	require.True(t, ok)
	require.Equal(t, "api-newer", id.name, "ownership mismatch invalidates stale cache hit immediately")
	require.Equal(t, "app=api,version=v2", id.labels)
}

func TestPeerRepair_InvalidateOnInventoryChange(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pods := []*common.SlimPod{
		slim("shop", "api-v1", "10.42.0.48", false, map[string]string{"app": "api"}),
	}
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: func() time.Time { return now }, pods: func() []*common.SlimPod { return pods }}

	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-v1", id.name)

	// Pod replaced without time advancement
	pods[0] = slim("shop", "api-v2", "10.42.0.48", false, map[string]string{"app": "api"})

	// Explicit invalidation for the IP
	r.invalidate("10.42.0.48")
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-v2", id.name)

	// Global invalidation
	pods[0] = slim("shop", "api-v3", "10.42.0.48", false, map[string]string{"app": "api"})
	r.invalidate()
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-v3", id.name)
}

func TestPeerRepair_BoundedCacheAndExpiration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: func() time.Time { return now }, pods: func() []*common.SlimPod { return nil }}

	// Insert more entries than maxPeerEntries
	for i := 0; i < maxPeerEntries+50; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		r.lookup(ip)
	}
	require.LessOrEqual(t, len(r.byIP), maxPeerEntries, "cache must be bounded to maxPeerEntries")

	// Advance time past miss TTL
	now = now.Add(peerMissTTL + time.Second)
	// Next lookup should prune expired entries
	r.lookup("1.2.3.4")
	require.Equal(t, 1, len(r.byIP), "expired entries must be pruned")
}

type networkTestDatasourceFields struct {
	ds        datasource.DataSource
	addrAcc   datasource.FieldAccessor
	kindAcc   datasource.FieldAccessor
	nameAcc   datasource.FieldAccessor
	nsAcc     datasource.FieldAccessor
	labelsAcc datasource.FieldAccessor
}

var networkTestDatasource = sync.OnceValue(func() networkTestDatasourceFields {
	ds, err := datasource.New(datasource.TypeSingle, "network")
	if err != nil {
		panic(err)
	}
	addrAcc, err := ds.AddField("endpoint.addr_raw.v4", api.Kind_Uint32)
	if err != nil {
		panic(err)
	}
	kindAcc, err := ds.AddField("endpoint.k8s.kind", api.Kind_String)
	if err != nil {
		panic(err)
	}
	nameAcc, err := ds.AddField("endpoint.k8s.name", api.Kind_String)
	if err != nil {
		panic(err)
	}
	nsAcc, err := ds.AddField("endpoint.k8s.namespace", api.Kind_String)
	if err != nil {
		panic(err)
	}
	labelsAcc, err := ds.AddField("endpoint.k8s.labels", api.Kind_String)
	if err != nil {
		panic(err)
	}
	if _, err := ds.AddField("endpoint.version", api.Kind_Uint8); err != nil {
		panic(err)
	}
	if _, err := ds.AddField("endpoint.port", api.Kind_Uint16); err != nil {
		panic(err)
	}
	if _, err := ds.AddField("endpoint.proto_raw", api.Kind_Uint16); err != nil {
		panic(err)
	}
	return networkTestDatasourceFields{
		ds:        ds,
		addrAcc:   addrAcc,
		kindAcc:   kindAcc,
		nameAcc:   nameAcc,
		nsAcc:     nsAcc,
		labelsAcc: labelsAcc,
	}
})

func newNetworkTestEvent(t *testing.T, ipStr, kind, namespace, name, labels string) (datasource.DataSource, datasource.Data, *utils.DatasourceEvent) {
	t.Helper()
	fields := networkTestDatasource()

	data, err := fields.ds.NewPacketSingle()
	require.NoError(t, err)

	ip := net.ParseIP(ipStr).To4()
	require.NotNil(t, ip)
	ipUint := binary.LittleEndian.Uint32(ip)

	require.NoError(t, fields.addrAcc.PutUint32(data, ipUint))
	require.NoError(t, fields.kindAcc.PutString(data, kind))
	require.NoError(t, fields.nameAcc.PutString(data, name))
	require.NoError(t, fields.nsAcc.PutString(data, namespace))
	require.NoError(t, fields.labelsAcc.PutString(data, labels))

	ev := &utils.DatasourceEvent{
		Datasource: fields.ds,
		Data:       data,
		EventType:  utils.NetworkEventType,
	}
	return fields.ds, data, ev
}

func TestPeerRepair_RepairPodEndpointWithMissingLabels(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pods := []*common.SlimPod{
		slim("production", "frontend", "10.42.1.20", false, map[string]string{"app": "frontend", "tier": "web"}),
	}
	r := &peerRepair{byIP: map[string]peerIdentity{}, now: func() time.Time { return now }, pods: func() []*common.SlimPod { return pods }}

	// Case 1: Kind is pod, but labels are empty -> should be repaired!
	ds, data, ev := newNetworkTestEvent(t, "10.42.1.20", string(igtypes.EndpointKindPod), "production", "frontend", "")
	repaired := r.repair(ds, data, ev)
	require.True(t, repaired, "pod with missing labels should be repaired")

	fields := networkTestDatasource()
	labels, err := fields.labelsAcc.String(data)
	require.NoError(t, err)
	require.Equal(t, "app=frontend,tier=web", labels)

	// Case 2: Non-pod kind (e.g. Service) -> must NOT be repaired
	ds, data, ev = newNetworkTestEvent(t, "10.42.1.20", string(igtypes.EndpointKindService), "production", "frontend-svc", "")
	repaired = r.repair(ds, data, ev)
	require.False(t, repaired, "service endpoints must not be repaired by peer repair")

	// Case 3: Pod endpoint that already has labels -> must NOT be repaired
	ds, data, ev = newNetworkTestEvent(t, "10.42.1.20", string(igtypes.EndpointKindPod), "production", "frontend", "app=existing")
	repaired = r.repair(ds, data, ev)
	require.False(t, repaired, "pod endpoints with existing labels must not be modified")
}
