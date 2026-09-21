package containerprofilemanager

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	containerinstance "github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// calculateSniffingTime/handleContainerMaxTime (lifecycle.go:174-226) used
// to apply a fixed cfg.MaxSniffingTime timer to every container, host included.
// Since the host pseudo-container runs indefinitely, that timer firing removed
// the host entry from the profile manager entirely, silently stopping host
// profile generation. The fix (addContainer, lifecycle.go) now skips arming
// that timer for utils.IsHostContainer, mirroring the existing IsHostContainer
// bypass convention (e.g. rule_manager.go:220-231).
//
// These two tests use a short MaxSniffingTime so the assertions do not have to
// wait for the real production default.

// newHostPseudoContainer builds the host pseudo-container event
// (ContainerPID == 1 is what utils.IsHostContainer keys on), shared by the
// host tests in this package that need to drive ContainerCallback.
//
// K8s is deliberately left at its zero value, matching the real production
// object built by GetHostAsContainer (pkg/containerwatcher/v2/
// container_watcher_collection.go) -- it has no backing Kubernetes Pod, so
// K8s.Namespace/PodName are empty there too. Pre-populating them here (as an
// earlier version of this helper did) would mask the exact bug this shape
// exists to catch: saveContainerProfile used to read container.K8s.Namespace
// directly for the CR's own Namespace field, so an empty K8s here reaching it
// unmodified would produce an empty-namespace CR that fails on create.
func newHostPseudoContainer() *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   armotypes.HostContainerID,
			ContainerName: "host",
			ContainerPID:  1,
		}},
	}
}

// TestHostContainerSurvivesMaxSniffingTime proves a host container is never
// finalized/deleted from the profile manager once the (short, for test speed)
// MaxSniffingTime deadline elapses.
func TestHostContainerSurvivesMaxSniffingTime(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-timer-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     50 * time.Millisecond, // short deadline a normal container would be finalized at
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: newHostPseudoContainer(),
	})

	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok || entry.data == nil {
			return false
		}
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return entry.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "host container was never registered in the profile manager")

	entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
	require.True(t, ok)
	entry.mu.RLock()
	timerArmed := entry.data.timer != nil
	entry.mu.RUnlock()
	assert.False(t, timerArmed, "host container must not have the max-sniffing-time timer armed")

	// Wait well past what would be a normal container's MaxSniffingTime deadline.
	time.Sleep(10 * cfg.MaxSniffingTime)

	_, stillExists := cpm.getContainerEntry(armotypes.HostContainerID)
	assert.True(t, stillExists, "host container must survive past MaxSniffingTime, not be finalized/deleted")
}

// TestNonHostContainerStillFinalizesAtMaxSniffingTime proves the host bypass did
// not change finalization behavior for regular containers: a non-host container
// is still finalized and removed once its MaxSniffingTime deadline elapses.
func TestNonHostContainerStillFinalizesAtMaxSniffingTime(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "container-timer-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	const containerID = "container-1"

	cfg := config.Config{
		InitialDelay:        time.Minute,
		UpdateDataPeriod:    time.Minute,
		MaxSniffingTime:     50 * time.Millisecond,
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	k8sObjectCacheMock.SetSharedContainerData(containerID, &objectcache.WatchedContainerData{
		InstanceID: &containerinstance.InstanceID{
			ApiVersion:    "apps/v1",
			Namespace:     "default",
			Kind:          "Pod",
			Name:          "pod-1",
			ContainerName: "app",
		},
		ContainerID:   containerID,
		PodName:       "pod-1",
		Namespace:     "default",
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: containerID}},
		},
		ParentWorkloadSelector: &metav1.LabelSelector{},
		PreRunningContainer:    false,
	})

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

	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
			ContainerID:   containerID,
			ContainerName: "app",
			ContainerPID:  1234,
		}},
		K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{
			Namespace: "default",
			PodName:   "pod-1",
		}},
	}

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(containerID)
		if !ok {
			return false
		}
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return entry.data != nil && entry.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "container was never registered in the profile manager")

	entry, ok := cpm.getContainerEntry(containerID)
	require.True(t, ok)
	timerArmed := func() bool {
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		// The timer's deadline is short enough (see MaxSniffingTime above) that
		// it could in principle have already fired and cleared entry.data by
		// the time this lock is acquired. require.NotNil calls t.FailNow(),
		// which exits via runtime.Goexit -- routing it through this closure
		// (rather than inline) ensures the deferred RUnlock still runs instead
		// of leaving the mutex held forever.
		require.NotNil(t, entry.data, "container entry data was cleared before the timer-armed assertion could run")
		return entry.data.timer != nil
	}()
	assert.True(t, timerArmed, "non-host container must still have the max-sniffing-time timer armed")

	// The timer fires, handleContainerMaxTime sends ContainerReachedMaxTime through
	// the monitoring goroutine, which then deletes the container entry.
	require.Eventually(t, func() bool {
		_, exists := cpm.getContainerEntry(containerID)
		return !exists
	}, 2*time.Second, 10*time.Millisecond, "non-host container must still be finalized/deleted once MaxSniffingTime elapses")
}

// TestContainerCallback_ReplayedAddDoesNotOrphanEarlierEntry proves
// registration is a get-or-insert, not an unconditional overwrite. The
// container-watcher collection is known to replay AddContainer notifications
// (see host_sbom.go's identical comment about the host pseudo-container).
// Before the fix, a replay created a second ContainerEntry and goroutine
// while the first kept running with no way to ever be signalled to stop by
// deleteContainer, which only ever looks up "the current" entry in the map.
func TestContainerCallback_ReplayedAddDoesNotOrphanEarlierEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-replay-queue-*")
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

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	addEvent := containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: newHostPseudoContainer(),
	}
	cpm.ContainerCallback(addEvent)

	var firstEntry *ContainerEntry
	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok {
			return false
		}
		firstEntry = entry
		return true
	}, 2*time.Second, 10*time.Millisecond, "container was never registered after the first add")

	// Replay the exact same AddContainer notification.
	cpm.ContainerCallback(addEvent)
	time.Sleep(50 * time.Millisecond) // let a (wrongly) spawned second add settle, if any

	secondEntry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
	require.True(t, ok)
	assert.Same(t, firstEntry, secondEntry,
		"a replayed add must not replace the tracked entry -- the original monitor must remain the one in the map")
}

// TestContainerCallback_ReplayDuringFailingRegistrationRetries proves that a
// replayed AddContainer notification which races in while an earlier
// registration attempt for the same container is still pending -- and that
// earlier attempt then fails -- retries registration itself instead of
// silently leaving the container untracked forever.
//
// addContainerEntryIfAbsent's ready channel closes on BOTH success and
// failure of a registration attempt (see addContainerWithTimeout's
// error/timeout branches), so a replay that only waited for closure and then
// assumed success would be wrong: it must check whether the entry survived,
// and if not, retry the get-or-insert with its own entry.
func TestContainerCallback_ReplayDuringFailingRegistrationRetries(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-replay-fail-queue-*")
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

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	containerID := armotypes.HostContainerID

	// Simulate a first registration attempt that is already in-flight (its
	// own goroutine hasn't reached success or failure yet): insert a bare
	// entry directly, exactly as addContainerWithTimeout does before it calls
	// addContainer.
	firstAttempt := &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
	require.True(t, cpm.addContainerEntryIfAbsent(containerID, firstAttempt))

	// Start the "replay" -- a second AddContainer notification racing in
	// while the first attempt is still pending -- on its own goroutine, since
	// it blocks on <-firstAttempt.ready.
	done := make(chan struct{})
	go func() {
		defer close(done)
		cpm.addContainerWithTimeout(newHostPseudoContainer())
	}()

	// Give the replay goroutine time to observe the existing entry and start
	// waiting on its ready channel.
	time.Sleep(20 * time.Millisecond)

	// Now fail the first attempt, exactly as addContainerWithTimeout's own
	// error/timeout branches do: close ready, then remove the entry.
	firstAttempt.readyOnce.Do(func() { close(firstAttempt.ready) })
	cpm.removeContainerEntry(containerID)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("replay never completed after the first attempt failed")
	}

	entry, ok := cpm.getContainerEntry(containerID)
	require.True(t, ok, "the replay must retry registration and end up tracked, not silently give up because entry.ready was already closed by the failed first attempt")
	assert.NotSame(t, firstAttempt, entry, "the tracked entry must be the replay's own successful registration, not the failed first attempt")

	require.Eventually(t, func() bool {
		e, ok := cpm.getContainerEntry(containerID)
		if !ok {
			return false
		}
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.data != nil && e.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "the retried registration must actually complete with shared data attached")
}

// TestAddContainer_HostRecordsLearningPeriodWithoutArmingTimer proves that
// skipping the max-sniffing-time timer for host does not also skip recording
// LearningPeriod on the shared data. objectcache.GetLabels emits
// LearningPeriod regardless of container type, and monitorContainer's own
// Completed-transition deadline for host now reuses this same field (rather
// than recomputing it, since calculateSniffingTime applies random jitter and
// a second call would silently drift from the value reported here) -- so a
// zero LearningPeriod would both misreport "0s" in host profile labels and
// make host's Completed transition fire immediately.
func TestAddContainer_HostRecordsLearningPeriodWithoutArmingTimer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-learning-period-queue-*")
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

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: newHostPseudoContainer(),
	})

	require.Eventually(t, func() bool {
		entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok {
			return false
		}
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return entry.data != nil && entry.data.watchedContainerData != nil
	}, 2*time.Second, 10*time.Millisecond, "host was never registered")

	entry, ok := cpm.getContainerEntry(armotypes.HostContainerID)
	require.True(t, ok)
	entry.mu.RLock()
	learningPeriod := entry.data.watchedContainerData.LearningPeriod
	timerArmed := entry.data.timer != nil
	entry.mu.RUnlock()

	assert.NotZero(t, learningPeriod, "LearningPeriod must be recorded for host, matching cfg.MaxSniffingTime, even though its timer is never armed")
	assert.Equal(t, cfg.MaxSniffingTime, learningPeriod)
	assert.False(t, timerArmed, "the max-sniffing-time timer must still never be armed for host")
}

// TestHostContainerProfile_ReachesCompletedWithoutStopping proves the fix for
// the deeper consequence of skipping host's max-sniffing-time timer:
// containerprofilecache.go's tryPopulateEntry only caches profiles whose
// status is terminal (Completed or TooLarge) -- without a separate path to
// Completed, the host profile would never be installed for
// GetProjectedContainerProfile or visible to profile-dependent CEL rules, no
// matter how much data it collected. monitorContainer now flips status to
// Completed once the same duration a real container's timer would use has
// elapsed, but -- unlike ContainerReachedMaxTime -- does not stop monitoring:
// this proves both halves, that Completed is reached AND that the container
// is still tracked (and still ticking) well past that point.
func TestHostContainerProfile_ReachesCompletedWithoutStopping(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-completed-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		InitialDelay:        20 * time.Millisecond,
		UpdateDataPeriod:    20 * time.Millisecond,
		MaxSniffingTime:     5 * time.Millisecond, // must have elapsed well before the first tick
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	// WatchedContainerData has no internal lock -- by design, it is only ever
	// mutated from the single monitorContainer goroutine that owns it. Reading
	// its fields from this goroutine while that one is concurrently ticking
	// would itself be a data race, so synchronize on the same
	// completionNotifier callback production code already uses to announce a
	// Completed transition (see monitoring.go), rather than polling entry
	// state directly.
	notifier := &completionNotifierMock{completed: make(chan string, 1)}
	cpm.SetCompletionNotifier(notifier)

	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: newHostPseudoContainer(),
	})

	select {
	case containerID := <-notifier.completed:
		assert.Equal(t, armotypes.HostContainerID, containerID)
	case <-time.After(2 * time.Second):
		t.Fatal("host profile never reached Completed once its learning window elapsed")
	}

	// Prove monitoring did not stop: the entry must still exist well after
	// the Completed transition, and no second completion notification must
	// fire on subsequent ticks (Completed must not be re-announced or regress
	// to Ready).
	time.Sleep(100 * time.Millisecond)
	_, ok := cpm.getContainerEntry(armotypes.HostContainerID)
	require.True(t, ok, "host must still be tracked well after reaching Completed -- Completed must not stop monitoring")
	select {
	case containerID := <-notifier.completed:
		t.Fatalf("completion must only be notified once, got a second notification for %q", containerID)
	default:
	}
}

// completionNotifierMock implements objectcache.CompletionNotifier, recording
// each NotifyContainerCompleted call onto a channel so tests can synchronize
// on the same happens-before edge production code uses (channel send/receive)
// instead of racily polling WatchedContainerData fields from outside its
// owning goroutine.
type completionNotifierMock struct {
	completed chan string
}

func (m *completionNotifierMock) NotifyContainerCompleted(containerID string) {
	m.completed <- containerID
}

// TestDeleteContainer_HostSkipsTerminationExitCodeLookup proves that if the
// host pseudo-container is ever removed before its profile reaches a
// terminal status (an unexpected but possible ordering), deleteContainer
// does not call GetTerminationExitCode -- which would retry for its full
// 30-second backoff window looking for a Kubernetes pod status that will
// never exist for host, then mark the profile Failed. This uses a long
// InitialDelay/MaxSniffingTime so the Completed-transition tick has not
// fired yet, isolating this guard from monitorContainer's own fix.
func TestDeleteContainer_HostSkipsTerminationExitCodeLookup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "host-delete-queue-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	t.Setenv("QUEUE_DIR", tempDir)

	cfg := config.Config{
		InitialDelay:        time.Hour, // no tick within this test's window
		UpdateDataPeriod:    time.Hour,
		MaxSniffingTime:     time.Hour,
		MaxJitterPercentage: 0,
		MaxTsProfileSize:    10 * 1024 * 1024,
	}

	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	hostData := hostidentity.BuildHostWatchedContainerData("node-1")
	k8sObjectCacheMock.SetSharedContainerData(armotypes.HostContainerID, hostData)

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

	hostContainer := newHostPseudoContainer()
	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: hostContainer,
	})

	var entry *ContainerEntry
	require.Eventually(t, func() bool {
		e, ok := cpm.getContainerEntry(armotypes.HostContainerID)
		if !ok {
			return false
		}
		entry = e
		return true
	}, 2*time.Second, 10*time.Millisecond, "host was never registered")

	// addContainer writes watchedContainerData (via setContainerData) from its
	// own goroutine and only closes entry.ready once that is done, so
	// synchronizing on the channel -- instead of racily reading entry.data.*
	// from this goroutine -- gives the required happens-before relationship.
	select {
	case <-entry.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("host container was never fully registered in the profile manager")
	}

	// Status is still Ready/Initializing here (no tick has fired): removal
	// must not hang for anywhere near GetTerminationExitCode's 30s budget.
	// ContainerCallback dispatches deleteContainer on its own goroutine, so
	// wait on the entry actually being removed from the map (deleteContainer's
	// own completion signal) rather than on ContainerCallback's (immediate)
	// return.
	cpm.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: hostContainer,
	})

	require.Eventually(t, func() bool {
		_, exists := cpm.getContainerEntry(armotypes.HostContainerID)
		return !exists
	}, 3*time.Second, 10*time.Millisecond,
		"deleteContainer took far too long for host -- it likely fell through to GetTerminationExitCode's 30s backoff")
}
