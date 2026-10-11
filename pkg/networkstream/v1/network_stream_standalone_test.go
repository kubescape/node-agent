package networkstream

import (
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type standaloneSharedDataProbe struct {
	objectcache.K8sObjectCacheMock
	reads atomic.Int32
}

func (p *standaloneSharedDataProbe) GetSharedContainerData(string) *objectcache.WatchedContainerData {
	p.reads.Add(1)
	// A ready sentinel prevents a broken bypass from leaving a retry goroutine
	// behind and proves that enrichment was actually invoked.
	return hostidentity.BuildHostWatchedContainerData("test-node")
}

func TestContainerCallback_StandaloneNetworkIdentityDoesNotWaitForPodData(t *testing.T) {
	for _, tc := range []struct{ name, namespace, pod string }{
		{"standalone", "", ""}, {"namespace-only", "test", ""}, {"pod-only", "", "test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := newHostRegressionStream(t, "test-node")
			probe := &standaloneSharedDataProbe{}
			ns.k8sObjectCache = probe
			event := addContainerEvent("runtime-test", "runtime-name", tc.namespace, tc.pod)
			ns.ContainerCallback(event)
			time.Sleep(100 * time.Millisecond)
			assert.Zero(t, probe.reads.Load(), "standalone traffic must not start a Pod-data wait")
			ns.eventsStorageMutex.RLock()
			entity, exists := ns.networkEventsStorage.Entities["runtime-test"]
			ns.eventsStorageMutex.RUnlock()
			require.True(t, exists, "standalone traffic remains visible")
			assert.Equal(t, "runtime-name", entity.ContainerName)
			assert.Empty(t, entity.WorkloadName)
			event.Type = containercollection.EventTypeRemoveContainer
			ns.ContainerCallback(event)
			ns.eventsStorageMutex.RLock()
			_, exists = ns.networkEventsStorage.Entities["runtime-test"]
			ns.eventsStorageMutex.RUnlock()
			assert.False(t, exists, "standalone removal remains visible")
		})
	}
}
