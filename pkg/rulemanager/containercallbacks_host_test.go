package rulemanager

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartRuleManager_HostNeverWaitsForSharedData verifies the host path.
//
// Disposition: no new guard needed. startRuleManager keeps its pre-existing
// IsHostContainer bypass, so waitForSharedContainerData (containercallbacks.go)
// is never reached for host at all — which is what this asserts, structurally:
// rm.objectCache is left nil, so any shared-data read on the host path would
// panic with a nil-pointer dereference instead of quietly succeeding.
//
// This matters now that shared data is non-nil for host: the wait would no
// longer stall, so a lost bypass would no longer be visible as a hang and could
// regress silently.
func TestStartRuleManager_HostNeverWaitsForSharedData(t *testing.T) {
	rm := newTestRuleManager(t.Context())
	require.Nil(t, rm.objectCache, "the nil object cache is what makes any shared-data read fail loudly")

	container := hostContainer("ns", "pod-a")
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		rm.startRuleManager(container, "ns/pod-a/pod-a", done)
	}()

	close(done)

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("startRuleManager did not return for the host container")
	}
}

// TestContainerCallback_HostBypassesIgnoreContainer proves ContainerCallback's
// own IgnoreContainer gate -- which runs before startRuleManager's
// IsHostContainer bypass is ever reached -- does not drop the real host
// pseudo-container. GetHostAsContainer (pkg/containerwatcher/v2/
// container_watcher_collection.go) builds it with an empty K8s.Namespace, and
// an IncludeNamespaces allow-list that doesn't list "" is a realistic
// production config that would otherwise silently disable rule/alert
// evaluation for host entirely.
func TestContainerCallback_HostBypassesIgnoreContainer(t *testing.T) {
	rm := newTestRuleManager(t.Context())
	rm.cfg = config.Config{IncludeNamespaces: []string{"kube-system"}}

	container := &containercollection.Container{}
	container.Runtime.ContainerID = armotypes.HostContainerID
	container.Runtime.ContainerPID = 1
	// K8s left at its zero value: this is what GetHostAsContainer produces.

	k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)

	rm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	assert.True(t, rm.trackedContainers.Contains(k8sContainerID),
		"host must be tracked even though its empty namespace is not in IncludeNamespaces")
}

// TestWaitForSharedContainerData_HostResolves covers the site itself: if the
// wait is ever reached for host (directly, or by a future caller that drops the
// bypass), it now returns the synthetic identity promptly instead of spinning
// on exponential backoff, and the data it returns is the host's own — not a
// half-populated entry that would produce an empty Wlid downstream.
func TestWaitForSharedContainerData_HostResolves(t *testing.T) {
	objCache := &objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData(armotypes.HostContainerID, hostidentity.BuildHostWatchedContainerData("node-1"))

	rm := newTestRuleManager(t.Context())
	rm.objectCache = objCache

	start := time.Now()
	data, err := rm.waitForSharedContainerData(armotypes.HostContainerID)

	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Less(t, time.Since(start), time.Second, "present data must return immediately, not after a backoff cycle")
	assert.Equal(t, armotypes.HostContainerID, data.ContainerID)
	assert.Equal(t, "wlid://cluster-unknown/namespace-host/host-node-1", data.Wlid,
		"the caller stores sharedData.Wlid; an empty one would be silently dropped")
}
