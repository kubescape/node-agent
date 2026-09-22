package v1

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	"github.com/kubescape/workerpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// busyScannerClient returns ErrScannerBusy for the first busyCalls container
// scans and a fixed error afterwards, so both halves of the policy -- the
// retry window and what happens once its ceiling is reached -- are reachable.
type busyScannerClient struct {
	busyCalls int32
	calls     atomic.Int32
	after     error
}

func (b *busyScannerClient) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	if b.calls.Add(1) <= b.busyCalls {
		return nil, sbomscanner.ErrScannerBusy
	}
	return nil, b.after
}

func (b *busyScannerClient) ScanHostFilesystem(_ context.Context, _ sbomscanner.HostScanRequest) (*sbomscanner.HostScanResult, error) {
	return nil, errors.New("host path not exercised by these tests")
}
func (b *busyScannerClient) Ready() bool  { return true }
func (b *busyScannerClient) Close() error { return nil }

func newBusyTestManager(t *testing.T, fake *fakeSbomClient, client sbomscanner.SBOMScannerClient, reporter *recordingFailureReporter) *SbomManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              ctx,
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    client,
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          "v1.0.0",
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
		busyRetries:      newFailureRetries(),
		failureReporter:  reporter,
		pool:             workerpool.New(1),
		busyRetryDelayFn: func(int) time.Duration { return time.Millisecond },
	}
}

// Test_ContainerBusy_IsNotAScanFailure is the falsifiable half of the admission
// design on the container path.
//
// A busy sidecar means the scan was never dispatched. Treating it like a scan
// failure -- reportFailure, failureRetries, eventually Incomplete -- would turn
// transient contention into reported degradation, which is exactly the
// regression the TryAcquire-only admission design was rejected for.
func Test_ContainerBusy_IsNotAScanFailure(t *testing.T) {
	fake := newFakeSbomClient()
	reporter := &recordingFailureReporter{}
	// Busy for the first attempt, then succeed-shaped failure never reached: the
	// retry lands on a non-busy response.
	client := &busyScannerClient{busyCalls: 1, after: errors.New("scan failed")}
	mgr := newBusyTestManager(t, fake, client, reporter)

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	require.NoError(t, err)

	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	// Immediately after the busy response, nothing has been reported or counted.
	assert.Zero(t, reporter.count(), "a busy sidecar must not be reported as a scan failure")
	_, counted := mgr.failureRetries.Get(sbomName)
	assert.False(t, counted, "a busy sidecar must not consume the failure budget")
	_, crashCounted := mgr.crashLoopRetries.Get(sbomName)
	assert.False(t, crashCounted, "a busy sidecar must not consume the crash-loop budget")
	assert.Zero(t, fake.patchCalls, "a busy sidecar must not mark any terminal status")

	// The retry is scheduled onto the pool rather than slept out inline, so the
	// call above returned promptly and the second attempt arrives shortly after.
	assert.Eventually(t, func() bool { return client.calls.Load() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"the busy scan must be re-submitted to the worker pool")
}

// Test_ContainerBusy_DoesNotBlockTheWorkerPool proves the backoff runs off the
// pool. workerpool.New(1) means a sleep inside the worker would head-of-line
// block every other container's SBOM generation on the node for the whole
// backoff window.
func Test_ContainerBusy_DoesNotBlockTheWorkerPool(t *testing.T) {
	fake := newFakeSbomClient()
	client := &busyScannerClient{busyCalls: 1, after: errors.New("scan failed")}
	mgr := newBusyTestManager(t, fake, client, &recordingFailureReporter{})
	// A backoff long enough that a sleeping worker would make the assertion below
	// time out rather than pass by luck.
	mgr.busyRetryDelayFn = func(int) time.Duration { return 30 * time.Second }

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	ran := make(chan struct{})
	mgr.pool.Submit(func() { close(ran) }, "other-container-work")
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the busy backoff blocked the shared worker pool")
	}
}

// Test_ContainerBusy_BecomesARealFailureAtTheCeiling pins the other half of the
// bounded policy: the retry window is bounded, so a sidecar that stays busy
// indefinitely is eventually indistinguishable from a broken one and is handled
// as a genuine failure rather than retried forever.
func Test_ContainerBusy_BecomesARealFailureAtTheCeiling(t *testing.T) {
	fake := newFakeSbomClient()
	reporter := &recordingFailureReporter{}
	client := &busyScannerClient{busyCalls: 1000, after: errors.New("unreachable")}
	mgr := newBusyTestManager(t, fake, client, reporter)

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	require.NoError(t, err)

	// Drive the ceiling through the actual scheduled retry chain.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	assert.Eventually(t, func() bool {
		count, ok := mgr.failureRetries.Get(sbomName)
		return ok && count > 0
	}, 2*time.Second, 5*time.Millisecond,
		"once the retry ceiling is reached, a persistently busy sidecar becomes a real failure")
	assert.Eventually(t, func() bool { return reporter.count() > 0 }, 2*time.Second, 5*time.Millisecond)
}

// Test_ContainerBusy_NotRoutedThroughPendingScans pins the mechanism choice.
// pendingScans drains on scannerClient.Ready() == true, which a merely-busy
// sidecar already reports, so a scan parked there would be re-submitted at once
// and busy-loop instead of backing off.
func Test_ContainerBusy_NotRoutedThroughPendingScans(t *testing.T) {
	fake := newFakeSbomClient()
	client := &busyScannerClient{busyCalls: 1000, after: errors.New("unreachable")}
	mgr := newBusyTestManager(t, fake, client, &recordingFailureReporter{})
	mgr.busyRetryDelayFn = func(int) time.Duration { return time.Hour }

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	mgr.pendingMu.Lock()
	defer mgr.pendingMu.Unlock()
	assert.Empty(t, mgr.pendingScans, "a busy sidecar is not a down sidecar")
	assert.Empty(t, mgr.pendingOrder)
}

// Test_ContainerBusy_RetryTimerStopsOnShutdown mirrors
// Test_HostScan_BusyRetryStopsOnShutdown: scheduleBusyRetry's timer is
// selected against s.ctx specifically so a shutdown mid-backoff abandons the
// pending retry immediately, rather than firing a resubmission into a
// manager already being torn down.
func Test_ContainerBusy_RetryTimerStopsOnShutdown(t *testing.T) {
	fake := newFakeSbomClient()
	client := &busyScannerClient{busyCalls: 1000, after: errors.New("unreachable")}
	mgr := newBusyTestManager(t, fake, client, &recordingFailureReporter{})
	ctx, cancel := context.WithCancel(context.Background())
	mgr.ctx = ctx
	mgr.busyRetryDelayFn = func(int) time.Duration { return time.Hour }

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	cancel()
	require.Eventually(t, func() bool {
		mgr.busyMu.Lock()
		defer mgr.busyMu.Unlock()
		return len(mgr.busyPending) == 0
	}, time.Second, time.Millisecond)

	// The retry must never reach the worker pool after cancellation: submit a
	// sentinel and confirm it runs promptly, proving the pool was never
	// occupied by (or waiting behind) an abandoned retry resubmission.
	ran := make(chan struct{})
	mgr.pool.Submit(func() { close(ran) }, "sentinel-after-shutdown")
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("a retry timer fired into the pool after shutdown")
	}
}

// Repeated container notifications must not bypass the scheduled backoff or
// exhaust its budget before the retry actually runs.
func Test_ContainerBusy_DeduplicatesNotificationsDuringBackoff(t *testing.T) {
	client := &busyScannerClient{busyCalls: 1000}
	mgr := newBusyTestManager(t, newFakeSbomClient(), client, &recordingFailureReporter{})
	mgr.busyRetryDelayFn = func(int) time.Duration { return time.Hour }
	notif, status, tag, id := testNotifAndImageStatus()
	name, err := names.ImageInfoToSlug(tag, id)
	require.NoError(t, err)
	for range busyRetryMaxAttempts + 1 {
		mgr.processContainerWithMetadata(notif, nil, status, tag, id)
	}
	assert.Equal(t, int32(1), client.calls.Load())
	attempts, ok := mgr.busyRetries.Get(name)
	require.True(t, ok)
	assert.Equal(t, 1, attempts)
}

func Test_ContainerBusy_DeduplicatesQueuedRetry(t *testing.T) {
	client := &busyScannerClient{busyCalls: 1, after: errors.New("scan failed")}
	mgr := newBusyTestManager(t, newFakeSbomClient(), client, &recordingFailureReporter{})
	blocked := make(chan struct{})
	unblock := make(chan struct{})
	mgr.pool.Submit(func() { close(blocked); <-unblock }, "block-worker")
	<-blocked
	defer mgr.pool.StopWait()
	defer close(unblock)
	notif, status, tag, id := testNotifAndImageStatus()
	name, err := names.ImageInfoToSlug(tag, id)
	require.NoError(t, err)
	mgr.processContainerWithMetadata(notif, nil, status, tag, id)
	require.Eventually(t, func() bool { return mgr.pool.WaitingQueueSize() == 1 }, time.Second, time.Millisecond)
	for range 5 {
		mgr.processContainerWithMetadata(notif, nil, status, tag, id)
	}
	assert.Equal(t, int32(1), client.calls.Load())
	attempts, _ := mgr.busyRetries.Get(name)
	assert.Equal(t, 1, attempts)
	assert.Equal(t, 1, mgr.pool.WaitingQueueSize())
}

func Test_ContainerBusy_QueuedRetryStopsOnShutdown(t *testing.T) {
	mgr := newBusyTestManager(t, newFakeSbomClient(), &busyScannerClient{}, &recordingFailureReporter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.ctx = ctx
	blocked := make(chan struct{})
	unblock := make(chan struct{})
	mgr.pool.Submit(func() { close(blocked); <-unblock }, "block-worker")
	<-blocked
	var calls atomic.Int32
	require.True(t, mgr.scheduleBusyRetry("image", func() { calls.Add(1) }))
	require.Eventually(t, func() bool { return mgr.pool.WaitingQueueSize() == 1 }, time.Second, time.Millisecond)
	cancel()
	require.Eventually(t, func() bool {
		mgr.busyMu.Lock()
		defer mgr.busyMu.Unlock()
		return len(mgr.busyPending) == 0
	}, time.Second, time.Millisecond)
	close(unblock)
	mgr.pool.StopWait()
	assert.Zero(t, calls.Load())
}
