package rulemanager

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/contextdetection/detectors"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRuleManager builds a minimal RuleManager sufficient to exercise
// ContainerCallback/monitorContainer without a cluster.
func newTestRuleManager(ctx context.Context) *RuleManager {
	return &RuleManager{
		ctx:               ctx,
		cfg:               config.Config{},
		trackedContainers: mapset.NewSet[string](),
		detectorManager:   detectors.NewDetectorManager(nil),
	}
}

// hostContainer builds a container that IsHostContainer treats as a host
// container, so startRuleManager takes the monitorContainer-only path and
// never touches objectCache/podToWlid, keeping the test self-contained.
func hostContainer(namespace, podName string) *containercollection.Container {
	c := &containercollection.Container{}
	c.Runtime.ContainerID = armotypes.HostContainerID
	c.K8s.Namespace = namespace
	c.K8s.PodName = podName
	c.K8s.ContainerName = podName
	return c
}

// waitForCondition polls until cond returns true or the timeout elapses.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestMonitorContainer_ExitsOnDoneChannel pins that monitorContainer exits
// promptly when its own done channel is closed.
func TestMonitorContainer_ExitsOnDoneChannel(t *testing.T) {
	rm := newTestRuleManager(context.Background())
	container := hostContainer("ns", "pod-a")
	done := make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- rm.monitorContainer(container, "ns/pod-a/pod-a", done)
	}()

	close(done)

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("monitorContainer did not exit after its done channel was closed")
	}
}

// TestMonitorContainer_IgnoresSiblingDoneChannel pins the fix for
// https://github.com/kubescape/node-agent/issues/919: a monitorContainer
// goroutine must exit only in response to ITS OWN done channel, never a
// different registration's channel for the same container ID.
func TestMonitorContainer_IgnoresSiblingDoneChannel(t *testing.T) {
	rm := newTestRuleManager(context.Background())
	container := hostContainer("ns", "pod-a")
	ownDone := make(chan struct{})
	siblingDone := make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- rm.monitorContainer(container, "ns/pod-a/pod-a", ownDone)
	}()

	// Closing an unrelated channel must not affect this goroutine.
	close(siblingDone)

	select {
	case <-errCh:
		t.Fatal("monitorContainer exited in response to a sibling's done channel")
	case <-time.After(100 * time.Millisecond):
		// still running, as expected
	}

	close(ownDone)

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("monitorContainer did not exit after its own done channel was closed")
	}
}

// TestContainerCallback_FastRemoveAddDoesNotLeakGoroutine reproduces the
// race from issue #919: Add -> Remove -> Add for the same k8sContainerID
// happening faster than any polling interval. Before the fix, the first
// monitorContainer goroutine re-derived liveness from shared mutable state
// (rm.trackedContainers) on a timer, so it would see the ID "tracked again"
// after the second Add and never exit, permanently leaking one goroutine per
// such cycle. After the fix, each monitorContainer is scoped to its own
// done channel: only the registration that owns a given goroutine can stop
// it, so the first goroutine exits on the Remove that closed its channel
// and does not resurrect on the following Add.
func TestContainerCallback_FastRemoveAddDoesNotLeakGoroutine(t *testing.T) {
	rm := newTestRuleManager(context.Background())
	container := hostContainer("ns", "pod-a")
	k8sContainerID := utils.CreateK8sContainerID("ns", "pod-a", "pod-a")

	rm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	firstDone, ok := rm.trackedContainerDone.Load(k8sContainerID)
	require.True(t, ok, "expected a done channel to be registered after Add")

	rm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})

	rm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	secondDone, ok := rm.trackedContainerDone.Load(k8sContainerID)
	require.True(t, ok, "expected a done channel to be registered after re-Add")
	require.NotEqual(t, firstDone, secondDone, "re-Add must create a fresh, distinct done channel")

	// The first registration's channel must already be closed by the Remove
	// that preceded the re-Add -- this is what lets its monitorContainer
	// goroutine exit instead of leaking.
	select {
	case _, open := <-firstDone:
		assert.False(t, open, "first registration's done channel should be closed")
	default:
		t.Fatal("first registration's done channel is not closed")
	}

	// The second (current) registration's channel must still be open.
	ok = waitForCondition(t, time.Second, func() bool {
		select {
		case <-secondDone:
			return false
		default:
			return true
		}
	})
	assert.True(t, ok, "current registration's done channel must remain open")

	rm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	_, ok = rm.trackedContainerDone.Load(k8sContainerID)
	assert.False(t, ok, "done channel entry should be removed after the matching Remove")
}
