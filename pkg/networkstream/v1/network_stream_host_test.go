package networkstream

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHostRegressionStream builds a NetworkStream whose shared-data cache
// already holds the synthetic host entry — the condition this regression
// test exists for.
func newHostRegressionStream(t *testing.T, nodeName string) *NetworkStream {
	t.Helper()
	cache := &objectcache.K8sObjectCacheMock{}
	cache.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData(nodeName))
	return &NetworkStream{
		ctx:                  t.Context(),
		k8sObjectCache:       cache,
		nodeName:             nodeName,
		networkEventsStorage: armotypes.NetworkStream{Entities: map[string]armotypes.NetworkStreamEntity{nodeName: newHostEntity()}},
		unannouncedEntities:  map[string]struct{}{},
	}
}

func addContainerEvent(containerID, containerName, namespace, podName string) containercollection.PubSubEvent {
	c := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: igtypes.BasicRuntimeMetadata{ContainerID: containerID, ContainerName: containerName},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: igtypes.BasicK8sMetadata{Namespace: namespace, PodName: podName, ContainerName: containerName},
		},
	}
	return containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: c}
}

// TestContainerCallback_HostBehaviourUnchanged is a REGRESSION
// test. network_stream.go already handles host correctly and is deliberately
// left unmodified; what needed proving is that its behaviour did not change now
// that GetSharedContainerData returns a non-nil synthetic entry for host.
//
// Two things must still hold:
//  1. The host entity stays keyed by nodeName (not by the literal "host" ID).
//  2. enrichWorkloadDetails is NOT launched for host. If the bypass regressed,
//     the wait would now SUCCEED (it used to spin forever on nil) and stamp the
//     node entity with WorkloadName="host-<hostID>" / WorkloadKind="Node" from
//     the synthetic InstanceID labels — i.e. the regression is now silent and
//     data-corrupting rather than merely a hung goroutine.
func TestContainerCallback_HostBehaviourUnchanged(t *testing.T) {
	ns := newHostRegressionStream(t, "node-1")

	host := addContainerEvent(armotypes.HostContainerID, "host", "", "")
	ns.ContainerCallback(host)

	// Give any (incorrectly) spawned enrichment goroutine time to land.
	time.Sleep(200 * time.Millisecond)

	ns.eventsStorageMutex.RLock()
	defer ns.eventsStorageMutex.RUnlock()

	_, byHostID := ns.networkEventsStorage.Entities[armotypes.HostContainerID]
	assert.False(t, byHostID, `host must not be keyed by the literal "host" container ID`)

	entity, ok := ns.networkEventsStorage.Entities["node-1"]
	require.True(t, ok, "host must remain keyed by nodeName")
	assert.Equal(t, "", entity.WorkloadName, "host must not be enriched from the synthetic InstanceID labels")
	assert.Equal(t, "", entity.WorkloadKind, "host must not be enriched from the synthetic InstanceID labels")
	assert.Equal(t, armotypes.HostContainerID, entity.ContainerID)
}

// TestContainerCallback_NonHostStillEnriched is the positive control: it proves
// the assertions above would actually catch a lost host bypass, by showing that
// a real container on the same stream DOES get enriched from its InstanceID.
func TestContainerCallback_NonHostStillEnriched(t *testing.T) {
	ns := newHostRegressionStream(t, "node-1")
	ns.k8sObjectCache.SetSharedContainerData("cid-1", &objectcache.WatchedContainerData{
		InstanceID: hostidentity.BuildHostInstanceID("node-1"),
	})

	ns.ContainerCallback(addContainerEvent("cid-1", "c", "ns", "pod-a"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ns.eventsStorageMutex.RLock()
		entity := ns.networkEventsStorage.Entities["cid-1"]
		ns.eventsStorageMutex.RUnlock()
		if entity.WorkloadName != "" {
			assert.Equal(t, "host-node-1", entity.WorkloadName)
			assert.Equal(t, "Node", entity.WorkloadKind)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a non-host container was never enriched, so the host assertions prove nothing")
}

// TestContainerCallback_HostRemovalUnchanged pins the remove-side host bypass:
// removal must delete the nodeName-keyed entity, unchanged by the non-nil
// shared data.
func TestContainerCallback_HostRemovalUnchanged(t *testing.T) {
	ns := newHostRegressionStream(t, "node-1")
	ns.ContainerCallback(addContainerEvent(armotypes.HostContainerID, "host", "", ""))

	remove := addContainerEvent(armotypes.HostContainerID, "host", "", "")
	remove.Type = containercollection.EventTypeRemoveContainer
	ns.ContainerCallback(remove)

	ns.eventsStorageMutex.RLock()
	defer ns.eventsStorageMutex.RUnlock()
	_, ok := ns.networkEventsStorage.Entities["node-1"]
	assert.False(t, ok, "host removal must delete the nodeName-keyed entity")
}
