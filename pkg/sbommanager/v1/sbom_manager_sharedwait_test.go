package v1

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
)

// Test_waitForSharedContainerData_HonorsContextDeadline is the regression guard for #850:
// a container whose shared data never arrives must not block the caller indefinitely. Before
// the fix the wait ran on context.Background() to backoff's 15m DefaultMaxElapsedTime, which
// on the single-worker SBOM pool head-of-line-blocked SBOM generation node-wide.
func Test_waitForSharedContainerData_HonorsContextDeadline(t *testing.T) {
	sm := &SbomManager{k8sObjectCache: &objectcache.K8sObjectCacheMock{}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	data, err := sm.waitForSharedContainerData(ctx, "never-populated")
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Less(t, elapsed, 5*time.Second, "wait must be bounded by the context deadline, not backoff's 15m default")
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
