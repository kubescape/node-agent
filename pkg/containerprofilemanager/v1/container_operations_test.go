package containerprofilemanager

import (
	"context"
	"os"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddContainerWithTimeout_StaleFailureCleanupDoesNotDeleteNewerEntry
// proves the fix for a race in the duplicate-registration retry added
// earlier in this PR (see TestContainerCallback_ReplayDuringFailingRegistrationRetries
// in lifecycle_host_timer_test.go): a failed registration attempt's cleanup
// (in both addContainer's own internal early-failure branches and
// addContainerWithTimeout's outer error/timeout branches) used to call the
// unconditional removeContainerEntry(containerID). If a replayed
// AddContainer notification raced in after the failing attempt's entry was
// removed but before every one of that attempt's own cleanup calls had run
// (addContainer's internal cleanup and addContainerWithTimeout's outer
// cleanup both fire for the same failure), the replay's own successful,
// newer entry could be deleted out from under it by the failed attempt's
// stale, later cleanup call -- leaving the replay's monitor goroutine
// running with no tracked entry left to ever signal it to stop.
//
// removeContainerEntryIfMatch closes this: a cleanup call is now always
// conditional on the entry it holds still being the one currently in the
// map, so a stale cleanup for an already-superseded entry is a no-op.
func TestAddContainerWithTimeout_StaleFailureCleanupDoesNotDeleteNewerEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "stale-cleanup-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     time.Hour,
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	// No shared data registered for this container: addContainer's own
	// internal waitForSharedContainerData call fails once its context is
	// cancelled, exercising the real "failed to get shared data" early-
	// failure cleanup path in lifecycle.go's addContainer.
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}

	cpm, err := NewContainerProfileManager(
		context.Background(),
		cfg,
		&k8sclient.K8sClientMock{},
		k8sObjectCacheMock,
		&storage.StorageHttpClientMock{},
		&dnsmanager.DNSManagerMock{},
		&seccompmanager.SeccompManagerMock{},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	defer cpm.Close()

	containerID := "container-under-test"
	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   containerID,
			ContainerName: "test",
		}},
	}

	failingEntry := &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
	require.True(t, cpm.addContainerEntryIfAbsent(containerID, failingEntry))

	// Drive addContainer's own internal early-failure cleanup directly,
	// against an already-cancelled context so waitForSharedContainerData
	// fails immediately -- this is the exact internal cleanup path that
	// already removes failingEntry from the map before addContainer returns.
	expiredCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = cpm.addContainer(container, expiredCtx)
	require.Error(t, err, "addContainer must fail against an already-cancelled context")

	_, stillTracked := cpm.getContainerEntry(containerID)
	require.False(t, stillTracked, "addContainer's internal failure path must have already removed its own entry")

	// A replay now successfully registers a NEWER entry for the same
	// containerID, simulating addContainerWithTimeout's duplicate-
	// registration retry picking up where the failed attempt left off.
	newerEntry := &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
	require.True(t, cpm.addContainerEntryIfAbsent(containerID, newerEntry))

	// addContainerWithTimeout's own outer error branch now observes the same
	// failure addContainer already handled internally, and (before this fix)
	// called the unconditional removeContainerEntry(containerID) -- which
	// would have deleted newerEntry instead of the already-gone
	// failingEntry. Simulate exactly that stale cleanup call.
	removed := cpm.removeContainerEntryIfMatch(containerID, failingEntry)
	assert.False(t, removed, "a stale cleanup tied to the failed attempt's own entry must not report success once a newer entry has replaced it")

	tracked, ok := cpm.getContainerEntry(containerID)
	require.True(t, ok, "the newer entry must survive the failed attempt's stale cleanup")
	assert.Same(t, newerEntry, tracked)
}
