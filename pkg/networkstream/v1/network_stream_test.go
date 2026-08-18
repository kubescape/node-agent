package networkstream

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testNodeName = "test-node"

// stubResolver reports every address as resolved so buildNetworkEvent skips its
// net.LookupAddr fallback: these tests must not depend on the sandbox having DNS.
type stubResolver struct{}

var _ dnsmanager.DNSResolver = (*stubResolver)(nil)

func (stubResolver) ResolveIPAddress(string) (string, bool) { return "", true }
func (stubResolver) ResolveContainerProcessToCloudServices(string, uint32) mapset.Set[string] {
	return nil
}

// newTestStream builds a NetworkStream with KubernetesMode off, so there is no k8s
// inventory to reach for and sendNetworkEvent is a no-op. Events land on the host
// entity because k8sObjectCache is nil.
func newTestStream(t *testing.T, mgr processtree.ProcessTreeManager) *NetworkStream {
	t.Helper()
	ns, err := NewNetworkStream(context.Background(), config.Config{}, nil, stubResolver{}, testNodeName, nil, true, mgr)
	require.NoError(t, err)
	return ns
}

// newTestStreamWithChannel additionally wires a notification channel and a flush
// interval, so Start()'s ticker body can be exercised.
func newTestStreamWithChannel(t *testing.T, mgr processtree.ProcessTreeManager, ch chan armotypes.NetworkStream, interval time.Duration) *NetworkStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ns, err := NewNetworkStream(ctx, config.Config{NetworkStreamingInterval: interval}, nil, stubResolver{}, testNodeName, ch, true, mgr)
	require.NoError(t, err)
	return ns
}

// addContainerNotification is what the container collection publishes when a
// container appears, carrying the pod identity the stream entity is built from.
func addContainerNotification(containerID, containerName, namespace, podName string) containercollection.PubSubEvent {
	return containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:   containerID,
					ContainerName: containerName,
					ContainerPID:  4242, // not 1: IsHostContainer treats pid 1 as the host
				},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{Namespace: namespace, PodName: podName},
			},
		},
	}
}

func outboundEvent(pid uint32, addr string, port uint16) *utils.StructEvent {
	return &utils.StructEvent{
		Pid:         pid,
		PktType:     "OUTGOING",
		Proto:       "TCP",
		DstPort:     port,
		DstEndpoint: types.L3Endpoint{Addr: addr},
		Timestamp:   time.Now().UnixNano(),
	}
}

func treeFor(pid uint32, comm string) *armotypes.ProcessTree {
	return &armotypes.ProcessTree{ProcessTree: armotypes.Process{PID: pid, Comm: comm}}
}

// containerEvent is an outbound event attributed to a container, which is what
// every event outside the host's own namespace looks like.
func containerEvent(containerID string, pid uint32, addr string, port uint16) *utils.StructEvent {
	event := outboundEvent(pid, addr, port)
	event.ContainerID = containerID
	return event
}

// TestHandleNetworkEvent_ContainersKeepSeparateEntities: outside Kubernetes every
// event used to be folded onto the node entity, so an ECS task's containers were
// indistinguishable in the stream. Each container must own its entity.
func TestHandleNetworkEvent_ContainersKeepSeparateEntities(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock()) // k8sObjectCache nil: the host/ECS shape

	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)
	ns.handleNetworkEvent(containerEvent("container-b", 202, "5.6.7.8", 443), nil)

	require.Len(t, ns.networkEventsStorage.Entities["container-a"].Outbound, 1)
	require.Len(t, ns.networkEventsStorage.Entities["container-b"].Outbound, 1)
	assert.Empty(t, ns.networkEventsStorage.Entities[testNodeName].Outbound,
		"container traffic must not be attributed to the node")
}

// TestHandleNetworkEvent_UnannouncedEntityCarriesContainerIdentity: nothing announces an
// ECS container to the stream, so the entity born on the first event is the only
// place its kind and ID can come from.
func TestHandleNetworkEvent_UnannouncedEntityCarriesContainerIdentity(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())

	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)

	entity := ns.networkEventsStorage.Entities["container-a"]
	assert.Equal(t, armotypes.NetworkStreamEntityKindContainer, entity.Kind)
	assert.Equal(t, "container-a", entity.ContainerID)
}

// TestHandleDnsEvent_ContainersKeepSeparateEntities mirrors the network-event case
// for DNS, which keys entities through the same path.
func TestHandleDnsEvent_ContainersKeepSeparateEntities(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	dnsEvent := func(containerID string) *utils.StructEvent {
		return &utils.StructEvent{ContainerID: containerID, DNSName: "evil.example.com.", DstPort: 53, Timestamp: time.Now().UnixNano()}
	}

	ns.handleDnsEvent(dnsEvent("container-a"), nil)
	ns.handleDnsEvent(dnsEvent("container-b"), nil)

	assert.Len(t, ns.networkEventsStorage.Entities["container-a"].Outbound, 1)
	assert.Len(t, ns.networkEventsStorage.Entities["container-b"].Outbound, 1)
	assert.Empty(t, ns.networkEventsStorage.Entities[testNodeName].Outbound)
}

// TestHandleNetworkEvent_HostTrafficStaysOnTheNodeEntity: only traffic that is not
// a container's — no container ID, or the host sentinel — collapses onto the node.
func TestHandleNetworkEvent_HostTrafficStaysOnTheNodeEntity(t *testing.T) {
	for _, containerID := range []string{"", armotypes.HostContainerID} {
		t.Run("containerID="+containerID, func(t *testing.T) {
			ns := newTestStream(t, processtree.NewProcessTreeManagerMock())

			ns.handleNetworkEvent(containerEvent(containerID, 101, "1.2.3.4", 443), nil)

			assert.Len(t, ns.networkEventsStorage.Entities[testNodeName].Outbound, 1)
			assert.Len(t, ns.networkEventsStorage.Entities, 1, "no entity may be created for the sentinel itself")
			assert.Equal(t, armotypes.NetworkStreamEntityKindHost, ns.networkEventsStorage.Entities[testNodeName].Kind)
		})
	}
}

// TestHandleNetworkEvent_KeyingIgnoresK8sObjectCache is the Kubernetes-inertness pin:
// the entity an event lands on is decided by the event's container ID alone. The cache
// used to force every event onto the node whenever it was absent, which is the whole
// bug — but the Kubernetes side of that condition must keep behaving exactly as it did.
func TestHandleNetworkEvent_KeyingIgnoresK8sObjectCache(t *testing.T) {
	for name, cache := range map[string]objectcache.K8sObjectCache{
		"kubernetes": &objectcache.K8sObjectCacheMock{},
		"host/ecs":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			ns, err := NewNetworkStream(context.Background(), config.Config{}, cache, stubResolver{}, testNodeName, nil, true, processtree.NewProcessTreeManagerMock())
			require.NoError(t, err)

			ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)
			ns.handleNetworkEvent(containerEvent("", 202, "5.6.7.8", 80), nil)

			assert.Len(t, ns.networkEventsStorage.Entities["container-a"].Outbound, 1)
			assert.Len(t, ns.networkEventsStorage.Entities[testNodeName].Outbound, 1)
		})
	}
}

// TestHandleNetworkEvent_AnnouncedContainerKeepsItsMetadata: where ContainerCallback
// does run, the entity it registered — with the pod identity the backend keys on —
// must not be replaced by the bare entity the event path would create.
func TestHandleNetworkEvent_AnnouncedContainerKeepsItsMetadata(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.ContainerCallback(addContainerNotification("container-a", "nginx", "default", "nginx-abc"))

	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)

	entity := ns.networkEventsStorage.Entities["container-a"]
	require.Len(t, entity.Outbound, 1)
	assert.Equal(t, "nginx", entity.ContainerName)
	assert.Equal(t, "default", entity.PodNamespace)
	assert.Equal(t, "nginx-abc", entity.PodName)
}

// TestContainerCallback_KeepsWhatTheEventPathAlreadyRecorded: the container watcher
// submits this callback to a worker pool, so a container's first connections can be
// recorded before it is announced — the window a new container's first egress falls
// into. Announcing it must add identity, not discard the traffic.
func TestContainerCallback_KeepsWhatTheEventPathAlreadyRecorded(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)

	ns.ContainerCallback(addContainerNotification("container-a", "nginx", "default", "nginx-abc"))

	entity := ns.networkEventsStorage.Entities["container-a"]
	assert.Len(t, entity.Outbound, 1, "traffic recorded before the announcement must survive it")
	assert.Equal(t, "nginx", entity.ContainerName, "and the announcement still supplies the identity")
}

// TestHandleNetworkEvent_KubernetesStillDropsUnknownEntities: in Kubernetes the
// container lifecycle is reliable, so a missing entity means the container was removed
// or is ignored — not that it was never announced. Creating one would emit a container
// with no pod or workload identity for a pod that is already gone, and the remove event
// is published BEFORE the container leaves the collection, so events keep arriving for
// it. Kubernetes keeps dropping, exactly as before.
func TestHandleNetworkEvent_KubernetesStillDropsUnknownEntities(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.cfg.KubernetesMode = true // the constructor cannot: it needs a live inventory

	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)

	assert.NotContains(t, ns.networkEventsStorage.Entities, "container-a")
	assert.Empty(t, ns.unannouncedEntities)
}

// TestHandleNetworkEvent_RestoresTheNodeEntityAsHost: the node entity is created at
// construction and re-created by every flush, so it is only ever missing because the
// host container was removed in between. It must come back as the host — never as a
// container whose ID is the node's name — and it must never become prunable.
func TestHandleNetworkEvent_RestoresTheNodeEntityAsHost(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	hostNotif := addContainerNotification(armotypes.HostContainerID, "", "", "")
	hostNotif.Container.Runtime.ContainerPID = 1 // what makes IsHostContainer true
	hostNotif.Type = containercollection.EventTypeRemoveContainer
	ns.ContainerCallback(hostNotif)
	require.NotContains(t, ns.networkEventsStorage.Entities, testNodeName)

	ns.handleNetworkEvent(containerEvent(armotypes.HostContainerID, 101, "1.2.3.4", 443), nil)

	entity := ns.networkEventsStorage.Entities[testNodeName]
	assert.Equal(t, armotypes.NetworkStreamEntityKindHost, entity.Kind)
	assert.Empty(t, entity.ContainerID, "the node is not a container")
	require.Len(t, entity.Outbound, 1)

	ns.snapshotAndClear()
	ns.snapshotAndClear()
	assert.Contains(t, ns.networkEventsStorage.Entities, testNodeName, "the node entity is never prunable")
}

// TestContainerCallback_LeavesTheNodeEntityAlone pins an inertness decision, not a
// desirable behaviour. With host monitoring on, the virtual host container is announced
// at startup and this callback overwrites the node entity — losing whatever it held and
// mislabelling it as a container until the next flush restores its kind. That is
// pre-existing and out of scope here, so the merge above is scoped to real containers:
// announcing the host container does nothing it did not already do. Do not "simplify"
// that condition away without deciding what the node entity's kind should be.
func TestContainerCallback_LeavesTheNodeEntityAlone(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(containerEvent(armotypes.HostContainerID, 101, "1.2.3.4", 443), nil)
	require.Len(t, ns.networkEventsStorage.Entities[testNodeName].Outbound, 1)

	hostNotif := addContainerNotification(armotypes.HostContainerID, "", "", "")
	hostNotif.Container.Runtime.ContainerPID = 1 // what makes IsHostContainer true
	ns.ContainerCallback(hostNotif)

	assert.Empty(t, ns.networkEventsStorage.Entities[testNodeName].Outbound,
		"the node entity behaves exactly as it did before this change")
}

// TestContainerCallback_RemoveLeavesNoDanglingMark: the prune set is only meaningful as
// a subset of the entity map. A mark left behind for an entity that is gone would have
// the prune reasoning about something that no longer exists.
func TestContainerCallback_RemoveLeavesNoDanglingMark(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)
	require.Contains(t, ns.unannouncedEntities, "container-a")

	notif := addContainerNotification("container-a", "nginx", "default", "nginx-abc")
	notif.Type = containercollection.EventTypeRemoveContainer
	ns.ContainerCallback(notif)

	assert.NotContains(t, ns.networkEventsStorage.Entities, "container-a")
	assert.NotContains(t, ns.unannouncedEntities, "container-a")
}

// TestSnapshotAndClear_PrunesIdleUnannouncedEntities: an entity created from an event has no
// lifecycle callback behind it, so nothing would ever remove it. Left in place it would
// ride along in every later payload — unbounded growth on a host with container churn.
// An interval with no traffic is the only "it is gone" signal available.
func TestSnapshotAndClear_PrunesIdleUnannouncedEntities(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)

	// The interval that carried its traffic must keep the entity: the events are in
	// the snapshot, and dropping the entity here would only churn it.
	snapshot := ns.snapshotAndClear()
	require.Len(t, snapshot.Entities["container-a"].Outbound, 1)
	assert.Contains(t, ns.networkEventsStorage.Entities, "container-a")

	// The pruning interval must not carry the dead entity either: it is dropped
	// before the snapshot is taken, so it never reaches a payload at all.
	snapshot = ns.snapshotAndClear() // a second interval, with nothing on it
	assert.NotContains(t, snapshot.Entities, "container-a")
	assert.NotContains(t, ns.networkEventsStorage.Entities, "container-a")
	assert.Contains(t, ns.networkEventsStorage.Entities, testNodeName, "the node entity is never pruned")
}

// TestSnapshotAndClear_KeepsIdleAnnouncedEntities: a container the callback registered
// is removed by the callback, not by silence. Pruning it on an idle interval would drop
// the workload identity that enrichWorkloadDetails resolved and never recover it.
func TestSnapshotAndClear_KeepsIdleAnnouncedEntities(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.ContainerCallback(addContainerNotification("container-a", "nginx", "default", "nginx-abc"))

	ns.snapshotAndClear()
	ns.snapshotAndClear()

	entity, ok := ns.networkEventsStorage.Entities["container-a"]
	require.True(t, ok, "an announced container outlives its idle intervals")
	assert.Equal(t, "nginx", entity.ContainerName)
}

// TestSnapshotAndClear_AnnouncingAnEntityStopsThePruning: the two paths can create
// the same entity in either order. Once the callback vouches for a container, silence
// must stop meaning "gone".
func TestSnapshotAndClear_AnnouncingAnEntityStopsThePruning(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(containerEvent("container-a", 101, "1.2.3.4", 443), nil)
	ns.ContainerCallback(addContainerNotification("container-a", "nginx", "default", "nginx-abc"))

	ns.snapshotAndClear()
	ns.snapshotAndClear()

	assert.Contains(t, ns.networkEventsStorage.Entities, "container-a")
}

// TestBuildNetworkEvent_PodEndpointWithoutK8sInventory: the inventory only exists in
// Kubernetes mode, so a pod- or service-kind endpoint reaching this code anywhere else
// would dereference a nil interface and take the agent down.
func TestBuildNetworkEvent_PodEndpointWithoutK8sInventory(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	require.Nil(t, ns.k8sInventory)

	for _, kind := range []types.EndpointKind{types.EndpointKindPod, types.EndpointKindService} {
		t.Run(string(kind), func(t *testing.T) {
			event := outboundEvent(101, "1.2.3.4", 443)
			event.DstEndpoint = types.L3Endpoint{Addr: "1.2.3.4", Kind: kind}

			assert.NotPanics(t, func() { ns.handleNetworkEvent(event, nil) })
			assert.Len(t, ns.networkEventsStorage.Entities[testNodeName].Outbound, 1,
				"the connection is still recorded, only its Kubernetes enrichment is missing")
		})
	}
}

// TestHandleNetworkEvent_TwoProcessesSameEndpoint pins the DATA LOSS this change
// fixes, not merely the attribution: the batch key is address/port/protocol with
// first-writer-wins, so the second process's connection is silently DISCARDED —
// it never reaches the wire under any process identity at all.
func TestHandleNetworkEvent_TwoProcessesSameEndpoint(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, 5_000_000_000)
	mgr.SetProcessBootTimeNs(202, 7_010_000_000)
	ns := newTestStream(t, mgr)

	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))
	ns.handleNetworkEvent(outboundEvent(202, "1.2.3.4", 443), treeFor(202, "wget"))

	entity := ns.networkEventsStorage.Entities[testNodeName]
	require.Len(t, entity.Outbound, 2, "both processes' connections to one endpoint must survive the batch; today the second is dropped")

	refs := map[string]string{}
	for key, ev := range entity.Outbound {
		require.NotNil(t, ev.ProcessRef, "every attributed connection carries a processRef")
		assert.True(t, strings.HasSuffix(key, "/"+ev.ProcessRef.String()),
			"batch key %q must end with the event's own ref %q", key, ev.ProcessRef.String())
		require.NotNil(t, ev.ProcessTree)
		refs[ev.ProcessRef.String()] = ev.ProcessTree.ProcessTree.Comm
	}
	// The comm proves each surviving entry kept its OWN process's data rather than
	// inheriting the first writer's.
	assert.Equal(t, map[string]string{"101/5000000000": "curl", "202/7010000000": "wget"}, refs)
}

// TestHandleNetworkEvent_SameProcessSameEndpoint: first-writer-wins is retained
// for one process, so the batch does not grow per repeated connection.
func TestHandleNetworkEvent_SameProcessSameEndpoint(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, 5_000_000_000)
	ns := newTestStream(t, mgr)

	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))
	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))

	assert.Len(t, ns.networkEventsStorage.Entities[testNodeName].Outbound, 1)
}

// TestHandleNetworkEvent_UnknownStartTime: a zero StartTimeNs is legal pid-only
// identity (process not yet procfs-scanned, or a Kubernetes-mode host process).
// The ref must still be emitted — dropping it would lose attribution entirely
// for that population.
func TestHandleNetworkEvent_UnknownStartTime(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock()) // reports 0 for every pid
	ns.handleNetworkEvent(outboundEvent(303, "5.6.7.8", 80), nil)

	entity := ns.networkEventsStorage.Entities[testNodeName]
	require.Len(t, entity.Outbound, 1)
	for key, ev := range entity.Outbound {
		require.NotNil(t, ev.ProcessRef)
		assert.Equal(t, "303/0", ev.ProcessRef.String())
		assert.Equal(t, "5.6.7.8/80/TCP/303/0", key)
	}
}

// TestHandleNetworkEvent_NoPidKeepsLegacyKey: with no pid there is nothing to
// attribute, and the key must stay byte-identical to today's format — no
// trailing separator — so an unattributed key can never collide with an
// attributed one (which always carries two more components).
func TestHandleNetworkEvent_NoPidKeepsLegacyKey(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleNetworkEvent(outboundEvent(0, "9.9.9.9", 53), nil)

	entity := ns.networkEventsStorage.Entities[testNodeName]
	require.Len(t, entity.Outbound, 1)
	for key, ev := range entity.Outbound {
		assert.Equal(t, "9.9.9.9/53/TCP", key)
		assert.Nil(t, ev.ProcessRef, "pid 0 is not an identity")
	}
}

// TestHandleDnsEvent_TwoProcessesSameDomain: the same first-writer-wins data loss
// exists for two processes querying one domain.
func TestHandleDnsEvent_TwoProcessesSameDomain(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, 5_000_000_000)
	mgr.SetProcessBootTimeNs(202, 7_010_000_000)
	ns := newTestStream(t, mgr)

	dnsEvent := func(pid uint32) *utils.StructEvent {
		return &utils.StructEvent{Pid: pid, DNSName: "evil.example.com.", DstPort: 53, Timestamp: time.Now().UnixNano()}
	}
	ns.handleDnsEvent(dnsEvent(101), treeFor(101, "curl"))
	ns.handleDnsEvent(dnsEvent(202), treeFor(202, "wget"))

	entity := ns.networkEventsStorage.Entities[testNodeName]
	require.Len(t, entity.Outbound, 2, "both processes' DNS queries must survive the batch")
	for key, ev := range entity.Outbound {
		require.NotNil(t, ev.ProcessRef)
		assert.Equal(t, "evil.example.com./"+ev.ProcessRef.String(), key)
		assert.Equal(t, "evil.example.com.", ev.DNSName, "the DNS name itself must not absorb the ref")
	}
}

func TestNewNetworkStream(t *testing.T) {
	tests := []struct {
		name            string
		cfg             config.Config
		expectedTimeout time.Duration
	}{
		{
			name: "with http exporter config and custom timeout",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						TimeoutSeconds: 10,
					},
				},
			},
			expectedTimeout: 10 * time.Second,
		},
		{
			name: "with http exporter config but no timeout",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						TimeoutSeconds: 0,
					},
				},
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
		{
			name: "without http exporter config",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: nil,
				},
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
		{
			name: "kubernetes mode disabled",
			cfg: config.Config{
				KubernetesMode: false,
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			nodeName := "test-node"
			eventsChannel := make(chan armotypes.NetworkStream, 1)

			ns, err := NewNetworkStream(
				ctx,
				tt.cfg,
				nil, // k8sObjectCache
				nil, // dnsResolver
				nodeName,
				eventsChannel,
				true, // dnsSupport
				nil,  // processTreeManager
			)

			if err != nil {
				t.Fatalf("NewNetworkStream() error = %v", err)
			}

			if ns == nil {
				t.Fatal("NewNetworkStream() returned nil")
			}

			// Check HTTP client timeout
			if ns.httpClient.Timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout %v, got %v", tt.expectedTimeout, ns.httpClient.Timeout)
			}

			// Check that networkEventsStorage is initialized
			if ns.networkEventsStorage.Entities == nil {
				t.Error("networkEventsStorage.Entities should not be nil")
			}

			// Check that host entity is created
			hostEntity, exists := ns.networkEventsStorage.Entities[nodeName]
			if !exists {
				t.Errorf("Host entity for node %s should exist", nodeName)
			}

			if hostEntity.Kind != armotypes.NetworkStreamEntityKindHost {
				t.Errorf("Expected host entity kind %v, got %v", armotypes.NetworkStreamEntityKindHost, hostEntity.Kind)
			}

			if hostEntity.Inbound == nil || hostEntity.Outbound == nil {
				t.Error("Host entity Inbound and Outbound maps should be initialized")
			}

			// Check other fields are set correctly
			if ns.nodeName != nodeName {
				t.Errorf("Expected nodeName %s, got %s", nodeName, ns.nodeName)
			}

			if ns.dnsSupport != true {
				t.Error("Expected dnsSupport to be true")
			}

			if ns.eventsNotificationChannel != eventsChannel {
				t.Error("eventsNotificationChannel not set correctly")
			}
		})
	}
}

// TestSnapshotNetworkStream_OwnsItsEventMaps: the flush snapshot must own its
// Inbound/Outbound maps. Sharing them means the producer keeps writing into maps
// a consumer already holds — the race the flush path's 100 ms sleep exists to
// paper over.
func TestSnapshotNetworkStream_OwnsItsEventMaps(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, 5_000_000_000)
	ns := newTestStream(t, mgr)
	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))

	snap := snapshotNetworkStream(&ns.networkEventsStorage)
	require.Len(t, snap.Entities[testNodeName].Outbound, 1)

	// Mutate the LIVE maps in place, exactly as removeProcessTreeFromEvents did.
	live := ns.networkEventsStorage.Entities[testNodeName]
	for k, ev := range live.Outbound {
		ev.ProcessTree = nil
		live.Outbound[k] = ev
	}
	delete(live.Outbound, "gone")

	for _, ev := range snap.Entities[testNodeName].Outbound {
		assert.NotNil(t, ev.ProcessTree, "the snapshot must not see in-place mutation of the live storage")
	}
}

// TestFlush_ChannelSnapshotSurvivesTheProducer pins the channel contract end to end:
// what the consumer receives must still carry trees AND be immune to everything the
// producer does afterwards. Fails deterministically against the pre-attribution flush,
// which handed over the live storage struct and then stripped and cleared it.
func TestFlush_ChannelSnapshotSurvivesTheProducer(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	mgr.SetProcessBootTimeNs(101, 5_000_000_000)
	// Buffered so a later tick cannot block the producer: the pre-attribution flush
	// sent while holding eventsStorageMutex, so a full channel would deadlock this
	// test against its own handleNetworkEvent call rather than failing an assertion.
	ch := make(chan armotypes.NetworkStream, 16)
	ns := newTestStreamWithChannel(t, mgr, ch, 200*time.Millisecond)
	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))

	ns.Start()

	var received armotypes.NetworkStream
	select {
	case received = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no flush arrived on the notification channel")
	}

	// Wait for the producer to actually finish the flush — an emptied live storage is
	// the observable signal that its clear loop ran — then record another connection.
	require.Eventually(t, func() bool {
		ns.eventsStorageMutex.RLock()
		defer ns.eventsStorageMutex.RUnlock()
		return len(ns.networkEventsStorage.Entities[testNodeName].Outbound) == 0
	}, 5*time.Second, 5*time.Millisecond, "the flush never cleared the live storage")
	ns.handleNetworkEvent(outboundEvent(202, "9.9.9.9", 80), treeFor(202, "wget"))

	outbound := received.Entities[testNodeName].Outbound
	require.Len(t, outbound, 1, "the received snapshot must keep its own events after the producer clears and re-fills storage")
	for _, ev := range outbound {
		require.NotNil(t, ev.ProcessTree, "the channel consumer keeps trees — the host network sensor reads them")
		assert.Equal(t, "curl", ev.ProcessTree.ProcessTree.Comm)
		require.NotNil(t, ev.ProcessRef)
	}
}

// TestFlush_BlockedChannelSendHonoursShutdown: the send blocks deliberately, so a slow
// consumer applies backpressure instead of losing traffic — which leaks the goroutine
// unless it also selects on ctx. Nothing else here enters the blocked path, because the
// other channel tests buffer so the producer never blocks.
func TestFlush_BlockedChannelSendHonoursShutdown(t *testing.T) {
	mgr := processtree.NewProcessTreeManagerMock()
	ctx, cancel := context.WithCancel(context.Background())
	// Unbuffered and never read: the flush blocks on the send.
	ch := make(chan armotypes.NetworkStream)
	ns, err := NewNetworkStream(ctx, config.Config{NetworkStreamingInterval: 20 * time.Millisecond},
		nil, stubResolver{}, testNodeName, ch, true, mgr)
	require.NoError(t, err)
	ns.handleNetworkEvent(outboundEvent(101, "1.2.3.4", 443), treeFor(101, "curl"))

	ns.Start()

	// The flush is past the lock body once the live storage is cleared, so from here
	// it is parked on the send with nobody reading.
	require.Eventually(t, func() bool {
		ns.eventsStorageMutex.RLock()
		defer ns.eventsStorageMutex.RUnlock()
		return len(ns.networkEventsStorage.Entities[testNodeName].Outbound) == 0
	}, 5*time.Second, 5*time.Millisecond, "the flush never reached its channel send")

	cancel()
	// Give the parked select a moment to observe cancellation. Only ctx.Done() is
	// ready at this point — the send cannot be, because there is still no receiver —
	// so a correct implementation abandons the send and returns.
	time.Sleep(100 * time.Millisecond)

	// Now become a receiver. If the goroutine were still parked on a plain blocking
	// send it would hand us the snapshot; having exited, it never can.
	select {
	case <-ch:
		t.Fatal("the flush completed its channel send after ctx cancellation: it is still parked on a send that ignores shutdown")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestHandleDnsEvent_NoPidKeepsLegacyKey mirrors the network-event case: with no
// pid the DNS key stays the bare name, byte-identical to the old format.
func TestHandleDnsEvent_NoPidKeepsLegacyKey(t *testing.T) {
	ns := newTestStream(t, processtree.NewProcessTreeManagerMock())
	ns.handleDnsEvent(&utils.StructEvent{DNSName: "example.com.", DstPort: 53, Timestamp: time.Now().UnixNano()}, nil)

	entity := ns.networkEventsStorage.Entities[testNodeName]
	require.Len(t, entity.Outbound, 1)
	for key, ev := range entity.Outbound {
		assert.Equal(t, "example.com.", key)
		assert.Nil(t, ev.ProcessRef, "pid 0 is not an identity")
	}
}

// TestProcessRefFor_NoManager: the constructor accepts a nil process-tree manager
// (TestNewNetworkStream passes one), so the ref lookup must not dereference it.
func TestProcessRefFor_NoManager(t *testing.T) {
	ns := newTestStream(t, nil)
	assert.Nil(t, ns.processRefFor(101), "no manager means nothing to attribute, not a panic")
	assert.Nil(t, ns.processRefFor(0))
}

func TestCountConnections(t *testing.T) {
	assert.Zero(t, countConnections(&armotypes.NetworkStream{}))

	stream := &armotypes.NetworkStream{Entities: map[string]armotypes.NetworkStreamEntity{
		"a": {
			Inbound:  map[string]armotypes.NetworkStreamEvent{"i1": {}, "i2": {}},
			Outbound: map[string]armotypes.NetworkStreamEvent{"o1": {}},
		},
		"b": {Outbound: map[string]armotypes.NetworkStreamEvent{"o2": {}, "o3": {}}},
	}}
	assert.Equal(t, 5, countConnections(stream), "inbound and outbound across every entity")
}
