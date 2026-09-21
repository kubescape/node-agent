package containerwatcher

import (
	"sync"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostsensormanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/workerpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingK8sObjectCache wraps objectcache.K8sObjectCacheMock and records how
// many times SetSharedContainerData is invoked, and with what container ID,
// so the test can assert exactly-once semantics for the host pseudo-container.
type countingK8sObjectCache struct {
	objectcache.K8sObjectCacheMock

	mu            sync.Mutex
	setCalls      int
	setContainers []string
}

func (c *countingK8sObjectCache) SetSharedContainerData(containerID string, data *objectcache.WatchedContainerData) {
	c.mu.Lock()
	c.setCalls++
	c.setContainers = append(c.setContainers, containerID)
	c.mu.Unlock()
	c.K8sObjectCacheMock.SetSharedContainerData(containerID, data)
}

// countingObjectCache implements objectcache.ObjectCache and always returns
// the same countingK8sObjectCache instance, so calls across multiple
// callback invocations accumulate on one counter instead of a fresh mock.
type countingObjectCache struct {
	k8sCache *countingK8sObjectCache
}

func (c *countingObjectCache) K8sObjectCache() objectcache.K8sObjectCache {
	return c.k8sCache
}
func (c *countingObjectCache) ContainerProfileCache() objectcache.ContainerProfileCache {
	return &objectcache.ContainerProfileCacheMock{}
}
func (c *countingObjectCache) DnsCache() objectcache.DnsCache {
	return &objectcache.DnsCacheMock{}
}

var _ objectcache.ObjectCache = (*countingObjectCache)(nil)

// TestContainerCallbackAsync_HostContainer_UsesSyntheticIdentity proves that
// the host pseudo-container ends up with real (synthetic) shared data
// available via GetSharedContainerData("host") after the callback fires, and
// that the data is Wlid-based (not a zero-value struct).
func TestContainerCallbackAsync_HostContainer_UsesSyntheticIdentity(t *testing.T) {
	k8sCache := &countingK8sObjectCache{}
	oc := &countingObjectCache{k8sCache: k8sCache}

	cw := &ContainerWatcher{
		cfg:         config.Config{NodeName: "test-node"},
		objectCache: oc,
		metrics:     metricsmanager.NewMetricsMock(),
		// k8sClient is intentionally left nil: if the host branch ever falls
		// through to setSharedWatchedContainerData, it will call
		// cw.k8sClient.GetWorkload(...) on a nil *k8sinterface.KubernetesApi
		// and panic, failing this test.
	}

	container := &containercollection.Container{}
	container.Runtime.ContainerID = armotypes.HostContainerID

	require.NotPanics(t, func() {
		cw.containerCallbackAsync(containercollection.PubSubEvent{
			Type:      containercollection.EventTypeAddContainer,
			Container: container,
		})
	})

	data := k8sCache.GetSharedContainerData(armotypes.HostContainerID)
	require.NotNil(t, data, "expected shared container data to be set for host")
	assert.Equal(t, armotypes.HostContainerID, data.ContainerID)
	assert.NotEmpty(t, data.Wlid, "expected a synthetic Wlid to be built for the host pseudo-container")
	assert.Contains(t, data.Wlid, "test-node")

	assert.Equal(t, 1, k8sCache.setCalls, "expected exactly one SetSharedContainerData call for host")
	assert.Equal(t, []string{armotypes.HostContainerID}, k8sCache.setContainers)
}

// TestContainerCallback_HostContainer_SingleCallSite proves that dispatching
// the host AddContainer event through the same containerCallback/pool path
// used by StartContainerCollection's manual trigger (container_watcher_collection.go)
// results in exactly one SetSharedContainerData call for "host" - i.e. there
// is no second, racing call site.
func TestContainerCallback_HostContainer_SingleCallSite(t *testing.T) {
	k8sCache := &countingK8sObjectCache{}
	oc := &countingObjectCache{k8sCache: k8sCache}

	cw := &ContainerWatcher{
		// NamespaceName must be non-empty and distinct from the (empty)
		// synthetic container's namespace, otherwise Config.IgnoreContainer
		// treats every "" namespace container (including the host
		// pseudo-container) as belonging to node-agent's own namespace and
		// drops it via removeContainer instead of routing it to callbacks.
		cfg:         config.Config{NodeName: "test-node", NamespaceName: "kubescape"},
		objectCache: oc,
		metrics:     metricsmanager.NewMetricsMock(),
		pool:        workerpool.New(2),
	}
	cw.callbacks = []containercollection.FuncNotify{
		cw.containerCallbackAsync,
	}

	container := &containercollection.Container{}
	container.Runtime.ContainerID = armotypes.HostContainerID

	require.NotPanics(t, func() {
		cw.containerCallback(containercollection.PubSubEvent{
			Type:      containercollection.EventTypeAddContainer,
			Container: container,
		})
	})

	// containerCallback dispatches to the pool asynchronously; wait for all
	// submitted work to finish before asserting.
	cw.pool.StopWait()

	assert.Equal(t, 1, k8sCache.setCalls, "expected exactly one SetSharedContainerData call for host across the full registration flow")
	assert.Equal(t, []string{armotypes.HostContainerID}, k8sCache.setContainers)

	data := k8sCache.GetSharedContainerData(armotypes.HostContainerID)
	require.NotNil(t, data)
	assert.NotEmpty(t, data.Wlid)
}

// TestContainerCallback_HostBypassesIgnoreContainer proves containerCallback's
// own IgnoreContainer gate -- which runs before any callback (including
// containerCallbackAsync's host branch) is ever dispatched -- does not drop
// the real host pseudo-container. GetHostAsContainer (container_watcher_
// collection.go) builds it with an empty K8s.Namespace, and an
// IncludeNamespaces allow-list that doesn't list "" is a realistic production
// config that would otherwise silently disable host monitoring entirely.
func TestContainerCallback_HostBypassesIgnoreContainer(t *testing.T) {
	k8sCache := &countingK8sObjectCache{}
	oc := &countingObjectCache{k8sCache: k8sCache}

	cw := &ContainerWatcher{
		cfg:         config.Config{NodeName: "test-node", IncludeNamespaces: []string{"kube-system"}},
		objectCache: oc,
		metrics:     metricsmanager.NewMetricsMock(),
		pool:        workerpool.New(2),
	}
	cw.callbacks = []containercollection.FuncNotify{
		cw.containerCallbackAsync,
	}

	container := &containercollection.Container{}
	container.Runtime.ContainerID = armotypes.HostContainerID
	// K8s left at its zero value: this is what GetHostAsContainer produces.

	cw.containerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	cw.pool.StopWait()

	assert.Equal(t, 1, k8sCache.setCalls,
		"host must be processed even though its empty namespace is not in IncludeNamespaces")
}

// TestResolveHostID_RetriesAfterFailure proves that a failed resolution is
// NOT cached: only a successful hostID is memoized, so a transient failure
// (e.g. the HOST_ROOT mount not yet ready on an early replay) is retried on
// the next call instead of permanently breaking host monitoring for the
// process lifetime. Using sync.Once here would fail this test, since Once
// locks in the first call's outcome -- success or failure -- forever.
func TestResolveHostID_RetriesAfterFailure(t *testing.T) {
	// NodeName empty and no machine-id file underneath: ResolveHostID must fail.
	restore := hostsensormanager.SetHostFSPrefixForTest(t.TempDir())

	cw := &ContainerWatcher{cfg: config.Config{NodeName: ""}}

	_, err := cw.resolveHostID()
	require.Error(t, err, "resolveHostID must fail when neither NodeName nor machine-id is available")
	assert.Empty(t, cw.cachedHostID, "a failed resolution must not populate the cache")

	// The underlying condition clears (NodeName becomes available, as it would
	// once the DaemonSet's downward-API env var is actually populated).
	restore()
	cw.cfg.NodeName = "test-node"

	hostID, err := cw.resolveHostID()
	require.NoError(t, err, "resolveHostID must retry and succeed once the transient failure clears")
	assert.Equal(t, "test-node", hostID)
	assert.Equal(t, "test-node", cw.cachedHostID, "a successful resolution must now be cached")

	// A further call must reuse the cached value rather than re-resolving.
	cw.cfg.NodeName = "different-node"
	hostID, err = cw.resolveHostID()
	require.NoError(t, err)
	assert.Equal(t, "test-node", hostID, "once cached, a successful hostID must not be re-derived from a later cfg mutation")
}
