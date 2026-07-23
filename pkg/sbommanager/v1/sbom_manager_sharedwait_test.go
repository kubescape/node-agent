package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/workerpool"
	"github.com/stretchr/testify/assert"
)

// Test_waitForSharedContainerData_HonorsContextDeadline is the regression guard for the wait
// being bounded: a container whose shared data never arrives must stop at the context deadline,
// not run to backoff's 15m DefaultMaxElapsedTime. The wait runs in a goroutine so that if the
// bound regresses (ctx -> context.Background()) the test fails cleanly at 2s instead of blocking
// the whole package's test binary for 15m and panicking on go test's default timeout.
func Test_waitForSharedContainerData_HonorsContextDeadline(t *testing.T) {
	sm := &SbomManager{k8sObjectCache: &objectcache.K8sObjectCacheMock{}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	type result struct {
		data *objectcache.WatchedContainerData
		err  error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		data, err := sm.waitForSharedContainerData(ctx, "never-populated")
		done <- result{data, err}
	}()

	select {
	case r := <-done:
		assert.ErrorIs(t, r.err, context.DeadlineExceeded, "the context deadline must be what stopped the wait")
		assert.Nil(t, r.data)
		assert.Less(t, time.Since(start), 2*time.Second, "wait must end near the 200ms deadline, not backoff's 15m default")
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not honor the context deadline (regression: unbounded context) — would otherwise block for backoff's 15m default")
	}
}

// Test_waitForSharedContainerData_ReturnsWhenDataArrives verifies the happy path still resolves:
// once the shared data is populated, the bounded wait returns it without error.
func Test_waitForSharedContainerData_ReturnsWhenDataArrives(t *testing.T) {
	cache := &objectcache.K8sObjectCacheMock{}
	cache.SetSharedContainerData("c-1", &objectcache.WatchedContainerData{ImageTag: "tag", ImageID: "id"})
	sm := &SbomManager{k8sObjectCache: cache}

	ctx, cancel := context.WithTimeout(context.Background(), maxWaitForSharedContainerData)
	defer cancel()

	data, err := sm.waitForSharedContainerData(ctx, "c-1")

	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, "tag", data.ImageTag)
	assert.Equal(t, "id", data.ImageID)
}

// signalingSbomClient signals on created the moment CreateSBOM is called, then returns an error so
// processContainerWithMetadata bails immediately (before the syft path). Receiving on created
// therefore proves the submitted work actually ran on the pool worker.
type signalingSbomClient struct {
	*fakeSbomClient
	created chan string
}

func (c *signalingSbomClient) CreateSBOM(sbom *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	c.created <- sbom.Name
	return nil, errors.New("signaled: stop processing here")
}

func addContainerNotif(containerID string) containercollection.PubSubEvent {
	return containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{ContainerID: containerID},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "default",
					PodName:       "pod-" + containerID,
					ContainerName: containerID,
				},
			},
		},
	}
}

// Test_awaitAndSubmit_StuckContainerDoesNotBlockOthers is the #850 regression guard for the fix
// itself: it proves the shared-data wait no longer occupies the single pool worker. Container A's
// data never arrives (a stuck/short-lived container); container B's is already present. If the
// wait ran inline on the pool worker again, A would head-of-line-block B — so B's work reaching
// the worker while A is stuck is exactly what the fix guarantees.
func Test_awaitAndSubmit_StuckContainerDoesNotBlockOthers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // unblocks container A's still-waiting goroutine at test end

	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"
	cache := &objectcache.K8sObjectCacheMock{}
	cache.SetSharedContainerData("cB", &objectcache.WatchedContainerData{ImageTag: imageTag, ImageID: imageID})

	sig := &signalingSbomClient{fakeSbomClient: newFakeSbomClient(), created: make(chan string, 1)}
	sm := &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              ctx,
		k8sObjectCache:   cache,
		pool:             workerpool.New(1),
		processing:       mapset.NewSet[string](),
		storageClient:    sig,
		version:          "v1.0.0",
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
		waitCancels:      make(map[string]context.CancelFunc),
	}

	// Container A is stuck: awaitAndSubmit must return without blocking on the wait.
	returned := make(chan struct{})
	go func() {
		sm.awaitAndSubmit(addContainerNotif("cA"), nil, nil)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitAndSubmit blocked on the shared-data wait (#850 regression: wait not off the pool)")
	}

	// Container B has data present: its SBOM work must reach the pool worker promptly even though
	// A is still stuck, proving the stuck container does not head-of-line-block the node.
	sm.awaitAndSubmit(addContainerNotif("cB"), nil, nil)
	select {
	case <-sig.created:
	case <-time.After(5 * time.Second):
		t.Fatal("container B's SBOM work never reached the pool worker while A was stuck (#850 regression)")
	}
}

// Test_cancelWait_StopsInFlightWait proves the container-remove path cancels the wait promptly so
// a short-lived container can't park a goroutine for the full timeout.
func Test_cancelWait_StopsInFlightWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sm := &SbomManager{
		ctx:            ctx,
		k8sObjectCache: &objectcache.K8sObjectCacheMock{}, // data never arrives for "cX"
		pool:           workerpool.New(1),
		processing:     mapset.NewSet[string](),
		waitCancels:    make(map[string]context.CancelFunc),
	}

	sm.awaitAndSubmit(addContainerNotif("cX"), nil, nil)

	// The wait is registered; a remove event must cancel it, dropping the registry entry.
	assert.Eventually(t, func() bool {
		sm.waitCancelsMu.Lock()
		_, registered := sm.waitCancels["cX"]
		sm.waitCancelsMu.Unlock()
		return registered
	}, time.Second, 5*time.Millisecond, "wait should be registered while in flight")

	sm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: addContainerNotif("cX").Container,
	})

	assert.Eventually(t, func() bool {
		sm.waitCancelsMu.Lock()
		_, registered := sm.waitCancels["cX"]
		sm.waitCancelsMu.Unlock()
		return !registered
	}, 2*time.Second, 5*time.Millisecond, "remove event must cancel and drop the in-flight wait")
}
