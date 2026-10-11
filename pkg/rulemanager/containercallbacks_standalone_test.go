package rulemanager

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sharedDataProbe struct {
	objectcachev1.RuleObjectCacheMock
	reads atomic.Int32
}

func (c *sharedDataProbe) K8sObjectCache() objectcache.K8sObjectCache { return c }

func (c *sharedDataProbe) GetSharedContainerData(string) *objectcache.WatchedContainerData {
	c.reads.Add(1)
	return &objectcache.WatchedContainerData{Wlid: "wlid://cluster-test/namespace-test/pod-test"}
}

func TestStartRuleManager_StandaloneSkipsPodData(t *testing.T) {
	cases := []struct {
		name      string
		metadata  func(*containercollection.Container)
		wantReads int32
	}{
		{"standalone", func(*containercollection.Container) {}, 0},
		{"namespace only", func(c *containercollection.Container) { c.K8s.Namespace = "test" }, 0},
		{"pod only", func(c *containercollection.Container) { c.K8s.PodName = "test" }, 0},
		{"container name only", func(c *containercollection.Container) { c.K8s.ContainerName = "test" }, 0},
		{"pod UID only", func(c *containercollection.Container) { c.K8s.PodUID = "test-uid" }, 0},
		{"pod labels only", func(c *containercollection.Container) { c.K8s.PodLabels = map[string]string{"app": "test"} }, 0},
		{"sandbox only", func(c *containercollection.Container) { c.SandboxId = "test-sandbox" }, 0},
		{"addressable Pod without container name", func(c *containercollection.Container) { c.K8s.Namespace = "test"; c.K8s.PodName = "test" }, 1},
		{"pod", func(c *containercollection.Container) {
			c.K8s.Namespace = "test"
			c.K8s.PodName = "test"
			c.K8s.ContainerName = "app"
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := &sharedDataProbe{}
			rm := newTestRuleManager(t.Context())
			rm.objectCache = cache
			container := &containercollection.Container{}
			container.Runtime.ContainerID = "standalone-test"
			container.Runtime.ContainerPID = uint32(os.Getpid())
			tc.metadata(container)
			done := make(chan struct{})
			close(done)
			rm.startRuleManager(container, "test-key", done)
			assert.Equal(t, tc.wantReads, cache.reads.Load(), "only Kubernetes containers need Pod metadata")
			wlid, bound := rm.podToWlid.Load(container.K8s.Namespace + "/" + container.K8s.PodName)
			assert.Equal(t, tc.wantReads != 0, bound, "standalone containers must not create a synthetic Pod binding")
			if bound {
				assert.Equal(t, "wlid://cluster-test/namespace-test/pod-test", wlid)
			}
		})
	}
}

func TestContainerCallback_StandaloneRegistrationsAreIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rm := newTestRuleManager(ctx)
	rm.cfg.NamespaceName = "kubescape"
	rm.objectCache = &sharedDataProbe{}
	rm.mntnsRegistry = contextdetection.NewMntnsRegistry()
	containers := []*containercollection.Container{{Mntns: 101}, {Mntns: 102}}
	for i, c := range containers {
		c.Runtime.ContainerID = []string{"runtime-a", "runtime-b"}[i]
		c.Runtime.ContainerPID = uint32(os.Getpid())
		rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: c})
	}
	require.Equal(t, 2, rm.trackedContainers.Cardinality(), "empty Kubernetes fields must not merge independent runtime registrations")
	for _, c := range containers {
		info, ok := rm.mntnsRegistry.Lookup(c.Mntns)
		require.True(t, ok)
		assert.Equal(t, contextdetection.Standalone, info.Context())
		pid, ok := rm.containerIdToPid.Load(c.Runtime.ContainerID)
		require.True(t, ok)
		assert.Equal(t, c.ContainerPid(), pid)
	}
	firstKey := "standalone:" + containers[0].Runtime.ContainerID
	secondKey := "standalone:" + containers[1].Runtime.ContainerID
	firstDone, ok := rm.trackedContainerDone.Load(firstKey)
	require.True(t, ok)
	secondDone, ok := rm.trackedContainerDone.Load(secondKey)
	require.True(t, ok)
	rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: containers[0]})
	select {
	case <-firstDone:
	default:
		t.Fatal("removed registration still running")
	}
	select {
	case <-secondDone:
		t.Fatal("sibling registration was stopped")
	default:
	}
	_, ok = rm.mntnsRegistry.Lookup(containers[0].Mntns)
	assert.False(t, ok)
	assert.True(t, rm.trackedContainers.Contains(secondKey))
	rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: containers[0]})
	newDone, ok := rm.trackedContainerDone.Load(firstKey)
	require.True(t, ok)
	assert.NotEqual(t, firstDone, newDone)
	select {
	case <-newDone:
		t.Fatal("new registration inherits a closed channel")
	default:
	}
	for _, c := range containers {
		rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: c})
	}
	assert.Zero(t, rm.trackedContainers.Cardinality())
}

func TestContainerCallback_StandaloneRemovalRetainsRegistrationIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rm := newTestRuleManager(ctx)
	rm.cfg.NamespaceName = "kubescape"
	rm.objectCache = &sharedDataProbe{}
	rm.mntnsRegistry = contextdetection.NewMntnsRegistry()
	c := &containercollection.Container{Mntns: 103}
	c.Runtime.ContainerID = "runtime-late-enrichment"
	c.Runtime.ContainerPID = uint32(os.Getpid())
	rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: c})
	key := "standalone:" + c.Runtime.ContainerID
	done, ok := rm.trackedContainerDone.Load(key)
	require.True(t, ok)
	// Runtime metadata may be enriched after the original registration.
	c.K8s.Namespace, c.K8s.PodName, c.K8s.ContainerName = "test", "test-pod", "app"
	rm.ContainerCallback(containercollection.PubSubEvent{Type: containercollection.EventTypeRemoveContainer, Container: c})
	select {
	case <-done:
	default:
		t.Fatal("late enrichment stranded the original runtime registration")
	}
	assert.Zero(t, rm.trackedContainers.Cardinality())
}
