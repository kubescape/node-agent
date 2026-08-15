package networkstream

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
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
