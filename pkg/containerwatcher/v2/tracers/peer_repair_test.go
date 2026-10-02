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

func newTestPeerRepair(pods func() []*common.SlimPod) *peerRepair {
	r := newPeerRepair()
	r.initInv = nil
	if pods != nil {
		r.pods = pods
	}
	return r
}

func newTestPeerRepairWithInv(inv common.K8sInventoryCache) *peerRepair {
	r := newPeerRepair()
	r.initInv = nil
	r.inventory = inv
	if inv != nil {
		r.pods = inv.GetPods
	}
	return r
}

func TestPeerRepair_ReusedAddressResolvesToTheCurrentPod(t *testing.T) {
	pods := []*common.SlimPod{
		slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api", "pod-template-hash": "cc49b4b9f"}),
		slim("kube-system", "kube-proxy-x", "172.16.0.3", true, map[string]string{"k8s-app": "kube-proxy"}),
	}
	calls := 0
	r := newTestPeerRepair(func() []*common.SlimPod { calls++; return pods })
	// Use short miss TTL for testing retry after miss
	r.missTTL = 20 * time.Millisecond

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
	require.Equal(t, 4, calls, "misses are cached while positive hits validate current pod ownership")

	time.Sleep(25 * time.Millisecond)
	pods = append(pods, slim("shop", "late", "10.42.9.9", false, map[string]string{"app": "late"}))
	id, ok = r.lookup("10.42.9.9")
	require.True(t, ok, "a miss is retried after its short TTL and finds the pod that appeared")
	require.Equal(t, "late", id.name)

	// Rapid churn: during IP reuse, both old terminating pod and replacement pod exist in inventory
	pods = append(pods, slim("shop", "api-newer", "10.42.0.48", false, map[string]string{"app": "api"}))
	// Expected pod name disambiguates duplicate IP candidates
	id, ok = r.lookupWithExpected("10.42.0.48", "shop", "api-newer")
	require.True(t, ok)
	require.Equal(t, "api-newer", id.name, "expected pod identity disambiguates duplicate IP candidates during churn")

	// Once old terminating pod is evicted from inventory, raw lookup also resolves to the new pod
	pods = pods[1:]
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-newer", id.name)
}

func TestPodByIP_FirstNonHostMatch(t *testing.T) {
	pods := []*common.SlimPod{
		nil,
		slim("a", "hostnet", "10.0.0.1", true, nil),
		slim("a", "real", "10.0.0.1", false, nil),
	}
	require.Equal(t, "real", podByIP(pods, "10.0.0.1", "", "").Name)
	require.Nil(t, podByIP(pods, "10.0.0.2", "", ""))
	require.Equal(t, "", labelString(nil))
}

func TestPodByIP_AmbiguousMatches(t *testing.T) {
	pods := []*common.SlimPod{
		slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api", "version": "v1"}),
		slim("shop", "api-newer", "10.42.0.48", false, map[string]string{"app": "api", "version": "v2"}),
	}
	// Without expected name, ambiguous matches are declined to prevent nondeterministic stale attribution
	require.Nil(t, podByIP(pods, "10.42.0.48", "", ""), "ambiguous IP match without expected name must be declined")

	// With expected name, ambiguous matches are correctly disambiguated
	matched := podByIP(pods, "10.42.0.48", "shop", "api-newer")
	require.NotNil(t, matched)
	require.Equal(t, "api-newer", matched.Name)
}

func TestPeerRepair_OwnershipValidationOnRapidChurn(t *testing.T) {
	pods := []*common.SlimPod{
		slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api", "version": "v1"}),
	}
	r := newTestPeerRepair(func() []*common.SlimPod { return pods })

	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-old", id.name)

	// Rapid churn happens: pod is replaced with api-newer on same IP
	pods[0] = slim("shop", "api-newer", "10.42.0.48", false, map[string]string{"app": "api", "version": "v2"})

	// Plain lookup without expected pod validates against inventory; ownership mismatch drops old hit
	id, ok = r.lookupWithExpected("10.42.0.48", "shop", "api-newer")
	require.True(t, ok)
	require.Equal(t, "api-newer", id.name, "ownership mismatch invalidates stale cache hit immediately")
	require.Equal(t, "app=api,version=v2", id.labels)
}

func TestPeerRepair_InvalidateOnInventoryChange(t *testing.T) {
	pods := []*common.SlimPod{
		slim("shop", "api-v1", "10.42.0.48", false, map[string]string{"app": "api"}),
	}
	r := newTestPeerRepair(func() []*common.SlimPod { return pods })

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
	r := newTestPeerRepair(func() []*common.SlimPod { return nil })
	r.missTTL = 10 * time.Millisecond

	// Insert more entries than maxPeerEntries
	for i := 0; i < maxPeerEntries+50; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		r.lookup(ip)
	}
	require.LessOrEqual(t, r.negative.Len(), maxPeerEntries, "negative cache must be bounded to maxPeerEntries")

	time.Sleep(15 * time.Millisecond)
	require.False(t, r.isNegative("192.168.0.0"), "expired entries must not be returned")
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
	pods := []*common.SlimPod{
		slim("production", "frontend", "10.42.1.20", false, map[string]string{"app": "frontend", "tier": "web"}),
	}
	r := newTestPeerRepair(func() []*common.SlimPod { return pods })

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

	// Case 4: Kind is raw (KubeIPResolver miss) -> should be repaired into Pod with full metadata
	ds, data, ev = newNetworkTestEvent(t, "10.42.1.20", string(igtypes.EndpointKindRaw), "", "", "")
	repaired = r.repair(ds, data, ev)
	require.True(t, repaired, "raw endpoint from resolver miss should be repaired into pod")

	kind, err := fields.kindAcc.String(data)
	require.NoError(t, err)
	require.Equal(t, string(igtypes.EndpointKindPod), kind)
	name, err := fields.nameAcc.String(data)
	require.NoError(t, err)
	require.Equal(t, "frontend", name)
	labels, err = fields.labelsAcc.String(data)
	require.NoError(t, err)
	require.Equal(t, "app=frontend,tier=web", labels)

	// Case 5: Kind is empty (unresolved) -> should be repaired into Pod
	ds, data, ev = newNetworkTestEvent(t, "10.42.1.20", "", "", "", "")
	repaired = r.repair(ds, data, ev)
	require.True(t, repaired, "empty kind endpoint should be repaired into pod")
}

func TestPeerRepair_CachedLabelsRefreshedOnRelabeling(t *testing.T) {
	pod := slim("shop", "api", "10.42.0.48", false, map[string]string{"version": "v1"})
	r := newTestPeerRepair(func() []*common.SlimPod { return []*common.SlimPod{pod} })

	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "version=v1", id.labels)

	// Pod is relabeled without IP or name change
	pod.Labels = map[string]string{"version": "v2", "env": "prod"}
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "env=prod,version=v2", id.labels, "cached labels must be refreshed on relabeling")
}

type mockInventory struct {
	common.K8sInventoryCache
	podsByName   map[string]*common.SlimPod
	podsByIP     map[string]*common.SlimPod
	byNameCalls  int
	byIPCalls    int
	getPodsCalls int
	stopCalls    int
}

func (m *mockInventory) GetPodByName(ns, name string) *common.SlimPod {
	m.byNameCalls++
	return m.podsByName[ns+"/"+name]
}

func (m *mockInventory) GetPodByIp(ip string) *common.SlimPod {
	m.byIPCalls++
	return m.podsByIP[ip]
}

func (m *mockInventory) GetPods() []*common.SlimPod {
	m.getPodsCalls++
	var res []*common.SlimPod
	for _, p := range m.podsByName {
		res = append(res, p)
	}
	return res
}

func (m *mockInventory) Stop() {
	m.stopCalls++
}

func TestPeerRepair_IndexedInventoryValidation(t *testing.T) {
	pod := slim("shop", "api", "10.42.0.48", false, map[string]string{"app": "api"})
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{"shop/api": pod},
		podsByIP:   map[string]*common.SlimPod{"10.42.0.48": pod},
	}
	r := newTestPeerRepairWithInv(inv)

	// Identity-constrained lookup uses indexed GetPodByName
	id, ok := r.lookupWithExpected("10.42.0.48", "shop", "api")
	require.True(t, ok)
	require.Equal(t, "api", id.name)
	require.Equal(t, 1, inv.byNameCalls, "constrained lookup should use GetPodByName")
	require.Equal(t, 0, inv.getPodsCalls, "indexed lookup should not call GetPods")

	// Constrained hit validation also uses GetPodByName
	id, ok = r.lookupWithExpected("10.42.0.48", "shop", "api")
	require.True(t, ok)
	require.Equal(t, "api", id.name)
	require.Equal(t, 2, inv.byNameCalls, "constrained hit validation should use GetPodByName")
	require.Equal(t, 0, inv.getPodsCalls, "constrained hit validation should not call GetPods")

	// Raw lookup consults full pod set to detect potential IP recycling ambiguity
	r.invalidate()
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api", id.name)
	require.Equal(t, 1, inv.getPodsCalls, "raw lookup must consult GetPods to ensure address is unambiguous")

	// Raw lookup on CACHE HIT validates via indexed lookup in O(1) without calling GetPods
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api", id.name)
	require.Equal(t, 1, inv.getPodsCalls, "raw hit validation must use indexed lookups, not GetPods")
}

func TestPeerRepair_AmbiguousIPRawLookupDeclinesRepair(t *testing.T) {
	oldPod := slim("default", "terminating-pod", "10.42.0.99", false, map[string]string{"app": "old"})
	newPod := slim("default", "replacement-pod", "10.42.0.99", false, map[string]string{"app": "new"})
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{
			"default/terminating-pod": oldPod,
			"default/replacement-pod": newPod,
		},
		podsByIP: map[string]*common.SlimPod{"10.42.0.99": newPod}, // indexed cache picked newPod
	}
	r := newTestPeerRepairWithInv(inv)

	// Raw lookup must not pick indexed winner; it must consult complete pod set and decline repair on ambiguity
	_, ok := r.lookup("10.42.0.99")
	require.False(t, ok, "raw lookup must decline repair when multiple pods claim the recycled IP")

	// Constrained lookup with expected pod name disambiguates successfully
	id, ok := r.lookupWithExpected("10.42.0.99", "default", "replacement-pod")
	require.True(t, ok)
	require.Equal(t, "replacement-pod", id.name)
}

func TestPeerRepair_RawHitInvalidatedWhenIPRecycled(t *testing.T) {
	oldPod := slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api"})
	newPod := slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api"})
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{"shop/api-old": oldPod},
		podsByIP:   map[string]*common.SlimPod{"10.42.0.48": oldPod},
	}
	r := newTestPeerRepairWithInv(inv)

	// Cache oldPod
	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-old", id.name)

	// IP is reassigned in index to newPod and oldPod is deleted
	delete(inv.podsByName, "shop/api-old")
	inv.podsByName["shop/api-new"] = newPod
	inv.podsByIP["10.42.0.48"] = newPod

	// Subsequent raw lookup detects that byIP index points to a different pod, invalidating the old hit
	// and immediately resolving to the new pod owner
	id, ok = r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-new", id.name)
}

func TestPeerRepair_StaleExpectedIdentityDoesNotAssignPodOnDifferentIP(t *testing.T) {
	// Stale pod metadata points to "api-old", but "api-old" was moved to a different IP or deleted
	oldPod := slim("shop", "api-old", "10.42.0.99", false, map[string]string{"app": "api"})
	r := newTestPeerRepair(func() []*common.SlimPod { return []*common.SlimPod{oldPod} })

	// An event comes with recycled IP "10.42.0.50", but carries stale metadata expectedName="api-old"
	_, ok := r.lookupWithExpected("10.42.0.50", "shop", "api-old")
	require.False(t, ok, "must decline repair when expected pod does not own the event IP")
	_, inNeg := r.negative.Get("10.42.0.50")
	require.False(t, inNeg, "negative entry should not be cached for constrained miss")
}

func TestPeerRepair_StopReleasesInventory(t *testing.T) {
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{},
	}
	r := newTestPeerRepairWithInv(inv)

	r.stop()
	require.Equal(t, 1, inv.stopCalls, "stop must decrement inventory reference count")
	require.Nil(t, r.inventory, "inventory reference must be cleared after stop")

	// Subsequent stop is a no-op
	r.stop()
	require.Equal(t, 1, inv.stopCalls, "subsequent stop must not call inventory Stop again")
}

func TestPeerRepair_StopPreventsLateInitialization(t *testing.T) {
	initCalls := 0
	inv := &mockInventory{podsByName: map[string]*common.SlimPod{}}
	r := newPeerRepair()
	r.initInv = func() common.K8sInventoryCache {
		initCalls++
		r.inventory = inv
		return inv
	}

	r.stop()
	require.True(t, r.stopped)

	// Late lookup after stop must refuse initialization
	_, ok := r.lookup("10.42.0.1")
	require.False(t, ok)
	require.Equal(t, 0, initCalls, "late lookup after stop must not initialize inventory")
	require.Nil(t, r.inventory)
}

func TestPeerRepair_IdentityConstrainedMissDoesNotPoisonRawLookup(t *testing.T) {
	pod := slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api"})
	r := newTestPeerRepair(func() []*common.SlimPod { return []*common.SlimPod{pod} })

	// Lookup with a stale expected pod name fails
	_, ok := r.lookupWithExpected("10.42.0.48", "shop", "stale-pod")
	require.False(t, ok)
	_, inNeg := r.negative.Get("10.42.0.48")
	require.False(t, inNeg, "constrained miss must not cache negative entry under IP")

	// Subsequent unconstrained (raw) lookup finds the true IP owner immediately
	id, ok := r.lookup("10.42.0.48")
	require.True(t, ok)
	require.Equal(t, "api-new", id.name)
}

func TestPeerRepair_StaleExpectedIdentityRejectedDuringIPReuse(t *testing.T) {
	oldPod := slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api", "version": "v1"})
	newPod := slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api", "version": "v2"})
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{
			"shop/api-old": oldPod,
			"shop/api-new": newPod,
		},
		podsByIP: map[string]*common.SlimPod{
			"10.42.0.48": newPod,
		},
	}
	r := newTestPeerRepairWithInv(inv)

	// An event arrives with recycled IP "10.42.0.48", but carries stale metadata expectedName="api-old".
	// Even though api-old is still in inventory (terminating) and reports 10.42.0.48,
	// GetPodByIp already points to api-new. The lookup must decline repair and not fall back to api-old.
	_, ok := r.lookupWithExpected("10.42.0.48", "shop", "api-old")
	require.False(t, ok, "must decline repair when expected pod is stale and IP belongs to replacement pod")

	// Constrained lookup with the true current owner succeeds
	id, ok := r.lookupWithExpected("10.42.0.48", "shop", "api-new")
	require.True(t, ok)
	require.Equal(t, "api-new", id.name)
	require.Contains(t, id.labels, "version=v2")
}

func TestNewNetworkTracer_KubernetesModeGate(t *testing.T) {
	tracerOff := NewNetworkTracer(nil, nil, nil, nil, nil, nil, nil, nil, false)
	require.Nil(t, tracerOff.peers, "peers must be nil when kubernetesMode is false")

	tracerOn := NewNetworkTracer(nil, nil, nil, nil, nil, nil, nil, nil, true)
	require.NotNil(t, tracerOn.peers, "peers must be initialized when kubernetesMode is true")
	// Clean up to prevent any lingering background state
	_ = tracerOn.Stop()
}

func TestPeerRepair_NilIPIndexValidatedAgainstFullPodSet(t *testing.T) {
	oldPod := slim("shop", "api-old", "10.42.0.48", false, map[string]string{"app": "api", "version": "v1"})
	newPod := slim("shop", "api-new", "10.42.0.48", false, map[string]string{"app": "api", "version": "v2"})
	inv := &mockInventory{
		podsByName: map[string]*common.SlimPod{
			"shop/api-old": oldPod,
			"shop/api-new": newPod,
		},
		podsByIP: map[string]*common.SlimPod{}, // IP index entry was pruned or not yet populated (nil)
	}
	r := newTestPeerRepairWithInv(inv)

	// Multiple pods claim 10.42.0.48 in GetPods. Even though GetPodByName returns api-old,
	// the nil-index case detects the ambiguity via unambiguous full-IP lookup and declines repair.
	_, ok := r.lookupWithExpected("10.42.0.48", "shop", "api-old")
	require.False(t, ok, "must decline repair when IP index is nil but multiple pods claim the IP")

	// When old pod is gone from inventory and only newPod claims the IP, unambiguous lookup succeeds
	delete(inv.podsByName, "shop/api-old")
	id, ok := r.lookupWithExpected("10.42.0.48", "shop", "api-new")
	require.True(t, ok, "unambiguous full-IP owner must be accepted even when IP index is nil")
	require.Equal(t, "api-new", id.name)
}


