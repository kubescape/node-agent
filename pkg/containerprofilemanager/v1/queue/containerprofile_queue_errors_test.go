package queue

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// genericStatusError reproduces what client-go builds when the response body is not a
// Status object, which is what storage's QueueManager returns for an oversized request.
func genericStatusError(code int) error {
	return apierrors.NewGenericServerResponse(
		code, "POST",
		schema.GroupResource{Group: "spdx.softwarecomposition.kubescape.io", Resource: "containerprofiles"},
		"cattle-cluster-agent", "", 0, false,
	)
}

// relayedStatusError reproduces what client-go builds when the apiserver relays a plain
// (non-Status) error from the storage registry: the message is carried verbatim.
func relayedStatusError(message string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusInternalServerError,
		Reason:  metav1.StatusReasonUnknown,
		Message: message,
	}}
}

// relayedStatusErrorWithCode is relayedStatusError but with an explicit HTTP code, so tests
// can reproduce a 413 whose body happens to relay a sentinel's text.
func relayedStatusErrorWithCode(code int, message string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    int32(code),
		Reason:  metav1.StatusReasonUnknown,
		Message: message,
	}}
}

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantKind     failureKind
		wantSentinel error
	}{
		{
			name:     "nil error is not a failure",
			err:      nil,
			wantKind: failureRetryable,
		},
		{
			// The ISO Gruppe regression: QueueManager rejects on Content-Length with a
			// plain-text 413, so the error carries neither sentinel. A bare 413 is a
			// transport rejection of one delta, not an aggregate verdict, so it is split
			// rather than terminal.
			name:     "bare http 413 is split, not terminal",
			err:      genericStatusError(http.StatusRequestEntityTooLarge),
			wantKind: failureSplit,
		},
		{
			// Pins the §5.1 reordering: an authoritative sentinel always wins over a bare
			// status code, even when that status code happens to be 413.
			name:         "413 that relays ObjectTooLargeError is terminal, not split",
			err:          relayedStatusErrorWithCode(http.StatusRequestEntityTooLarge, file.ObjectTooLargeError.Error()),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "wrapped ObjectTooLargeError is terminal",
			err:          fmt.Errorf("saving profile: %w", file.ObjectTooLargeError),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "bare ObjectTooLargeError relayed by the apiserver is terminal",
			err:          relayedStatusError(file.ObjectTooLargeError.Error()),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			// storage prefixes the sentinel with the limit on the application-profile and
			// network-neighborhood paths, so exact string equality is not enough.
			name:         "prefixed ObjectTooLargeError relayed by the apiserver is terminal",
			err:          relayedStatusError("application profile size exceeds the limit of 40000: object is too large"),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectTooLargeError,
		},
		{
			name:         "bare ObjectCompletedError relayed by the apiserver is terminal",
			err:          relayedStatusError(file.ObjectCompletedError.Error()),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectCompletedError,
		},
		{
			name:         "wrapped ObjectCompletedError is terminal",
			err:          fmt.Errorf("saving profile: %w", file.ObjectCompletedError),
			wantKind:     failureTerminal,
			wantSentinel: file.ObjectCompletedError,
		},
		{
			// This is precisely the input whose classification changed from terminal to
			// retryable: matchesSentinel's substring fallback used to run against every
			// error shape, so a plain error whose text merely mentions the sentinel (e.g.
			// relayed by a proxy or ingress, not by the apiserver as a StatusError) would
			// misclassify as terminal and end learning. It is now restricted to
			// *apierrors.StatusError, where the message is known to be a relayed sentinel.
			name:     "non-StatusError error merely mentioning the sentinel is retryable",
			err:      errors.New("proxy error: upstream said object is too large"),
			wantKind: failureRetryable,
		},
		{
			name:     "server timeout is retryable",
			err:      relayedStatusError("the server has received too many requests and has asked us to try again later"),
			wantKind: failureRetryable,
		},
		{
			name:     "connection refused is retryable",
			err:      errors.New("dial tcp 10.96.0.1:443: connect: connection refused"),
			wantKind: failureRetryable,
		},
		{
			name:     "conflict is retryable",
			err:      genericStatusError(http.StatusConflict),
			wantKind: failureRetryable,
		},
		{
			name:     "internal server error is retryable",
			err:      genericStatusError(http.StatusInternalServerError),
			wantKind: failureRetryable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, reported := classifyFailure(tt.err)
			assert.Equal(t, tt.wantKind, kind)

			if tt.wantKind == failureTerminal {
				// The sentinel is what ContainerProfileManager.handleSaveProfileError
				// matches on to pick the terminal container status.
				assert.Equal(t, tt.wantSentinel, reported)
			} else {
				assert.Equal(t, tt.err, reported)
			}
		})
	}
}

// TestClassifyFailure_413IsSplitNotTerminal guards the specific regression: before this fix a
// 413 matched neither sentinel by string equality and was requeued forever; after it, a bare
// 413 must classify as failureSplit (not failureTerminal, and not failureRetryable either).
func TestClassifyFailure_413IsSplitNotTerminal(t *testing.T) {
	err := genericStatusError(http.StatusRequestEntityTooLarge)

	// Establish that the old exact-equality check really does miss this error, so the
	// test fails loudly if someone reintroduces it.
	assert.NotEqual(t, file.ObjectTooLargeError.Error(), err.Error())
	assert.NotEqual(t, file.ObjectCompletedError.Error(), err.Error())

	kind, reported := classifyFailure(err)
	assert.Equal(t, failureSplit, kind)
	assert.Equal(t, err, reported)
}

// alwaysFailingCreator returns the same error for every create, counts the calls, and records
// every profile it was asked to create (regardless of outcome) so tests can inspect what the
// queue actually attempted to send - including dropChunk's replacement stitch chunks.
type alwaysFailingCreator struct {
	mu       sync.Mutex
	err      error
	calls    int
	profiles []*v1beta1.ContainerProfile
}

func (c *alwaysFailingCreator) CreateContainerProfileDirect(p *v1beta1.ContainerProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.profiles = append(c.profiles, p.DeepCopy())
	return c.err
}

func (c *alwaysFailingCreator) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *alwaysFailingCreator) attemptedProfiles() []*v1beta1.ContainerProfile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*v1beta1.ContainerProfile(nil), c.profiles...)
}

// sizeGatedCreator rejects a create with a bare 413 while the profile still has more than
// threshold partitionable elements, and records everything it accepts. This gates on element
// count rather than bytes or elapsed time, so convergence is exact and deterministic.
type sizeGatedCreator struct {
	mu        sync.Mutex
	threshold int
	accepted  []*v1beta1.ContainerProfile
}

func (c *sizeGatedCreator) CreateContainerProfileDirect(p *v1beta1.ContainerProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if countPartitionableElements(&p.Spec) > c.threshold {
		return genericStatusError(http.StatusRequestEntityTooLarge)
	}

	c.accepted = append(c.accepted, p.DeepCopy())
	return nil
}

func (c *sizeGatedCreator) acceptedProfiles() []*v1beta1.ContainerProfile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*v1beta1.ContainerProfile(nil), c.accepted...)
}

// recordingCallback captures the errors the queue reports through ErrorCallback.
type recordingCallback struct {
	mu     sync.Mutex
	errors []error
}

func (r *recordingCallback) OnQueueError(_ *v1beta1.ContainerProfile, _ string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, err)
}

func (r *recordingCallback) captured() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errors...)
}

// startQueue starts a QueueData for testing. cfg is an overlay: any zero-valued field is
// filled with a fast test default. ErrorCallback is always taken from cb, not cfg.
func startQueue(t *testing.T, creator storage.ProfileCreator, cb ErrorCallback, cfg QueueConfig) *QueueData {
	t.Helper()

	if cfg.QueueName == "" {
		cfg.QueueName = "test-queue"
	}
	if cfg.QueueDir == "" {
		cfg.QueueDir = t.TempDir()
	}
	if cfg.MaxQueueSize == 0 {
		cfg.MaxQueueSize = 10
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 20 * time.Millisecond
	}
	if cfg.ItemsPerSegment == 0 {
		cfg.ItemsPerSegment = 10
	}
	cfg.ErrorCallback = cb

	qd, err := NewQueueData(context.Background(), creator, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = qd.Close() })

	qd.Start()
	return qd
}

// testProfile returns a minimal but production-shaped profile: a real (previousReportTimestamp,
// reportTimestamp] pair built from actual time.Now() calls (never time.Date, which would mask
// the monotonic-suffix bug - see parseReportTimestamp) plus a ReportSeriesIdMetadataKey
// annotation. Without these, queue-level split tests would silently only exercise
// chainHalves's refuse-and-drop path while appearing to pass.
//
// The name already carries a one-time-slug suffix (base + "-" + 32 hex chars), matching what
// every real profile name looks like (GetOneTimeSlug). freshOneTimeSlug regenerates a
// same-length suffix on top of it, so splitting never inflates the name - a short, sluggless
// name would make the regenerated 32-hex suffix dwarf a small partitionable payload and trip
// the byte-progress guard for reasons that have nothing to do with what a test is checking.
func testProfile() *v1beta1.ContainerProfile {
	prev := time.Now().Add(-time.Hour)
	rt := time.Now()

	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cattle-cluster-agent-0123456789abcdef0123456789abcdef",
			Namespace: "cattle-system",
			Annotations: map[string]string{
				helpersv1.ReportSeriesIdMetadataKey:          "test-series-id",
				helpersv1.PreviousReportTimestampMetadataKey: prev.String(),
				helpersv1.ReportTimestampMetadataKey:         rt.String(),
			},
		},
	}
}

// trackPeakQueueSize polls qd's queue size in the background and reports the maximum observed.
// Split tests use it to assert the queue never actually hit MaxQueueSize during the run, since
// hitting the cap would silently invalidate a "no data lost" assertion via LRU eviction.
func trackPeakQueueSize(qd *QueueData) (peak func() int, stop func()) {
	var mu sync.Mutex
	var max int
	var once sync.Once

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if s := qd.GetQueueSize(); s > max {
					mu.Lock()
					max = s
					mu.Unlock()
				}
			}
		}
	}()

	return func() int {
			mu.Lock()
			defer mu.Unlock()
			return max
		}, func() {
			once.Do(func() { close(done) })
		}
}

// TestQueueSplitsProfileOnHTTP413 replaces TestQueueEndsLearningOnHTTP413: after the fix, a
// bare 413 no longer ends learning. The queue must instead halve the rejected chunk and keep
// retrying both halves until storage accepts them.
func TestQueueSplitsProfileOnHTTP413(t *testing.T) {
	profile := testProfile()
	profile.Spec.Capabilities = []string{"cap-0", "cap-1", "cap-2", "cap-3", "cap-4", "cap-5", "cap-6", "cap-7"}

	creator := &sizeGatedCreator{threshold: 2}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxQueueSize: 32, RetryInterval: 20 * time.Millisecond})

	peak, stop := trackPeakQueueSize(qd)
	defer stop()

	require.NoError(t, qd.Enqueue(profile, "container-id"))

	assert.Eventually(t, func() bool {
		return qd.GetQueueSize() == 0 && len(creator.acceptedProfiles()) > 0
	}, 5*time.Second, 20*time.Millisecond, "expected the split chunks to eventually be accepted")

	stop()
	accepted := creator.acceptedProfiles()
	require.NotEmpty(t, accepted)

	baseName, _ := file.SplitProfileName(profile.Name)
	seen := map[string]bool{}
	var union []string
	var rows []tsRow

	for _, p := range accepted {
		for _, c := range p.Spec.Capabilities {
			assert.False(t, seen[c], "capability %q duplicated across accepted chunks", c)
			seen[c] = true
			union = append(union, c)
		}

		name, _ := file.SplitProfileName(p.Name)
		assert.Equal(t, baseName, name, "every accepted chunk must share the original's aggregate base name")

		rows = append(rows, rowOf(p))
	}

	assert.ElementsMatch(t, profile.Spec.Capabilities, union, "the union of accepted chunks must equal the original set exactly")
	assert.Empty(t, cb.captured(), "learning must never end on a 413 path")

	sortRowsDesc(rows)
	assertChainIsLinear(t, rows,
		profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		profile.Annotations[helpersv1.ReportTimestampMetadataKey])

	golden := consolidateGolden(rows)
	require.Len(t, golden, 1)

	assert.Less(t, peak(), 32, "the queue must never reach MaxQueueSize during the run")
}

// TestQueueDropsUnsplittableProfileOnHTTP413 is the floor case and the single most important
// regression guard for D2: a chunk that cannot be split further must still not end learning.
func TestQueueDropsUnsplittableProfileOnHTTP413(t *testing.T) {
	profile := testProfile()
	profile.Spec.Capabilities = []string{"only"}
	profile.Spec.SeccompProfile = v1beta1.SingleSeccompProfile{Name: "seccomp-1"}
	profile.Spec.ImageID = "sha256:deadbeef"
	profile.Spec.ImageTag = "v1.2.3"

	creator := &alwaysFailingCreator{err: genericStatusError(http.StatusRequestEntityTooLarge)}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxQueueSize: 8})

	peak, stop := trackPeakQueueSize(qd)
	defer stop()

	require.NoError(t, qd.Enqueue(profile, "container-id"))

	assert.Eventually(t, func() bool {
		return qd.GetQueueSize() == 0 && creator.callCount() >= 2
	}, 2*time.Second, 10*time.Millisecond, "expected the original and its replacement stitch to both be attempted")

	// No further attempts: the stitch is never itself re-stitched.
	callsAfterDrain := creator.callCount()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, callsAfterDrain, creator.callCount())

	stop()
	attempts := creator.attemptedProfiles()
	require.Len(t, attempts, 2, "exactly the original and its stitch replacement must be attempted")

	original := attempts[0]
	assert.Equal(t, []string{"only"}, original.Spec.Capabilities)

	stitch := attempts[1]
	assert.Equal(t, profile.Spec.SeccompProfile, stitch.Spec.SeccompProfile)
	assert.Equal(t, profile.Spec.ImageID, stitch.Spec.ImageID)
	assert.Equal(t, profile.Spec.ImageTag, stitch.Spec.ImageTag)
	assert.Empty(t, stitch.Spec.Capabilities)
	assert.Equal(t, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey], stitch.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
	assert.Equal(t, profile.Annotations[helpersv1.ReportTimestampMetadataKey], stitch.Annotations[helpersv1.ReportTimestampMetadataKey])

	assert.Empty(t, cb.captured(), "learning must never end on a 413 path, even in the floor case")
	assert.Equal(t, 0, qd.GetQueueSize())
	assert.Less(t, peak(), 8)
}

// TestQueueRespectsMaxSplitDepth bounds the split storm: with MaxSplitDepth set low, a
// richly-populated profile that always 413s must still terminate rather than split forever.
func TestQueueRespectsMaxSplitDepth(t *testing.T) {
	const maxSplitDepth = 2

	profile := testProfile()
	profile.Spec.Capabilities = []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	creator := &alwaysFailingCreator{err: genericStatusError(http.StatusRequestEntityTooLarge)}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxQueueSize: 64, MaxSplitDepth: maxSplitDepth})

	peak, stop := trackPeakQueueSize(qd)
	defer stop()

	require.NoError(t, qd.Enqueue(profile, "container-id"))

	// The queue can transiently read size 0 between an item being dequeued and its split
	// children (or stitch replacement) being re-enqueued within the same tick, so require
	// size 0 to hold across a settle window before treating the queue as actually drained -
	// otherwise this flakes by snapshotting callCount mid-tree-expansion.
	require.Eventually(t, func() bool {
		if qd.GetQueueSize() != 0 {
			return false
		}
		time.Sleep(50 * time.Millisecond)
		return qd.GetQueueSize() == 0
	}, 5*time.Second, 20*time.Millisecond, "expected the queue to drain rather than split forever")

	// The tree bounded by MaxSplitDepth, plus one stitch per dropped leaf, must stop growing.
	callsAfterDrain := creator.callCount()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, callsAfterDrain, creator.callCount(), "attempts must stop once the queue has drained")

	stop()
	assert.LessOrEqual(t, creator.callCount(), 1<<(maxSplitDepth+2),
		"total attempts must be bounded by the depth cap, not grow without limit")
	assert.Empty(t, cb.captured())
	assert.Less(t, peak(), 64)
}

// TestQueueDoesNotStitchAStitch is the B2 regression guard: without the IsStitch check, a
// dropped stitch would itself be stitched, forever, since neither drop path touches Attempts.
func TestQueueDoesNotStitchAStitch(t *testing.T) {
	profile := testProfile()
	profile.Spec.Capabilities = []string{"only"} // floor case: cannot split, must be dropped

	creator := &alwaysFailingCreator{err: genericStatusError(http.StatusRequestEntityTooLarge)}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxQueueSize: 8, RetryInterval: 10 * time.Millisecond})

	require.NoError(t, qd.Enqueue(profile, "container-id"))

	assert.Eventually(t, func() bool {
		return qd.GetQueueSize() == 0 && creator.callCount() >= 2
	}, 2*time.Second, 10*time.Millisecond)

	// Run for many more ticks than a runaway stitch->413->stitch loop would need to explode.
	time.Sleep(300 * time.Millisecond)

	assert.LessOrEqual(t, creator.callCount(), 3, "a dropped stitch must never itself be re-stitched")
	assert.Equal(t, 0, qd.GetQueueSize(), "the queue must drain rather than grow without limit")
	assert.Empty(t, cb.captured())
}

// TestQueuePersistsSplitDepth closes §8 assumption 4: SplitDepth and IsStitch must survive
// dque's gob-based persistence, or IsStitch failing to persist would silently restore the B2
// stitch->413->stitch loop across a restart.
func TestQueuePersistsSplitDepth(t *testing.T) {
	dir := t.TempDir()
	creator := &alwaysFailingCreator{}
	cb := &recordingCallback{}

	cfg := QueueConfig{
		QueueName:       "test-queue",
		QueueDir:        dir,
		MaxQueueSize:    10,
		RetryInterval:   time.Hour, // long enough that the processor never runs during this test
		ItemsPerSegment: 10,
		ErrorCallback:   cb,
	}

	qd, err := NewQueueData(context.Background(), creator, cfg)
	require.NoError(t, err)

	item := &QueuedContainerProfile{
		Profile:     testProfile(),
		ContainerID: "container-id",
		Attempts:    5,
		SplitDepth:  3,
		IsStitch:    true,
	}
	require.NoError(t, qd.queue.Enqueue(item))
	require.NoError(t, qd.Close())

	reopened, err := NewQueueData(context.Background(), creator, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	iface, err := reopened.queue.Dequeue()
	require.NoError(t, err)
	got, ok := iface.(*QueuedContainerProfile)
	require.True(t, ok)

	assert.Equal(t, 3, got.SplitDepth)
	assert.True(t, got.IsStitch)
	assert.Equal(t, 5, got.Attempts)
}

// TestQueueDropsProfileAfterMaxAttempts covers the general case: any error that never
// resolves must stop consuming the queue rather than starving newer profiles.
//
// It also covers issue #871: before the fix, exhausting MaxAttempts simply discarded the item,
// forking the container's report-timestamp chain with no replacement. Now the drop goes through
// dropChunk like any other, so a stitch carrying the original's (previousReportTimestamp,
// reportTimestamp] pair must be attempted too - and, since the creator here always fails, that
// stitch inherits the parent's already-exhausted Attempts and so is itself dropped after a
// single try, without ever being re-stitched (mirrors TestQueueDoesNotStitchAStitch).
func TestQueueDropsProfileAfterMaxAttempts(t *testing.T) {
	const maxAttempts = 3

	profile := testProfile()
	creator := &alwaysFailingCreator{err: errors.New("dial tcp 10.96.0.1:443: connect: connection refused")}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxAttempts: maxAttempts})

	require.NoError(t, qd.Enqueue(profile, "container-id"))

	assert.Eventually(t, func() bool {
		return creator.callCount() >= maxAttempts+1 && qd.GetQueueSize() == 0
	}, 2*time.Second, 10*time.Millisecond, "expected the profile and its replacement stitch to both be attempted")

	// The retry budget is a hard bound, and the stitch is never itself re-stitched, so no
	// further attempts happen once both have been dropped.
	callsAfterDrain := creator.callCount()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, callsAfterDrain, creator.callCount(), "no further attempts once the original and its stitch are both dropped")
	assert.Equal(t, maxAttempts+1, creator.callCount(), "the original gets its full budget, the stitch exactly one try")
	assert.Equal(t, 0, qd.GetQueueSize())
	assert.Empty(t, cb.captured(), "a retryable failure must not end learning for the container")

	attempts := creator.attemptedProfiles()
	require.Len(t, attempts, maxAttempts+1)

	stitch := attempts[maxAttempts]
	assert.NotEqual(t, profile.Name, stitch.Name)
	assert.Empty(t, stitch.Spec.Capabilities, "a stitch carries no size-bearing data")
	assert.Equal(t, profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey], stitch.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		"the stitch must preserve the dropped chunk's chain link")
	assert.Equal(t, profile.Annotations[helpersv1.ReportTimestampMetadataKey], stitch.Annotations[helpersv1.ReportTimestampMetadataKey],
		"the stitch must preserve the dropped chunk's chain link")
}

// TestDropChunk_StitchBacklogExhaustedForksWithoutReplacement covers a gap a review of this
// change found: dropChunk built and enqueued a repair stitch unconditionally, without checking
// the same in-flight backlog bound enforceMaxSize's own eviction loop respects. Left unfixed, a
// sustained run of MaxAttempts exhaustions could grow the backlog past the bound the eviction
// loop relies on to terminate promptly, since only enforceMaxSize's own path was gated. This
// pins that dropChunk (here reached via MaxAttempts exhaustion) must also check
// stitchBacklogFull and fall back to an unrepaired, forked drop once the backlog is already
// spent - never enqueueing a stitch or incrementing the backlog past its bound.
func TestDropChunk_StitchBacklogExhaustedForksWithoutReplacement(t *testing.T) {
	spy := newSpyMetrics()
	creator := &alwaysFailingCreator{err: errors.New("dial tcp 10.96.0.1:443: connect: connection refused")}
	cb := &recordingCallback{}
	qd := startQueue(t, creator, cb, QueueConfig{MaxAttempts: 1, MetricsManager: spy})

	// Simulate the backlog already sitting at its bound, e.g. from unrelated evictions or
	// prior drops, so this drop's own stitch must be refused rather than pushing it over.
	qd.stitchBacklog.Store(qd.maxStitchBacklog)

	require.NoError(t, qd.Enqueue(testProfile(), "container-id"))

	assert.Eventually(t, func() bool {
		return creator.callCount() >= 1 && qd.GetQueueSize() == 0
	}, 2*time.Second, 10*time.Millisecond, "expected the profile to be dropped after its single attempt")

	// No stitch was enqueued (the backlog was already full), so there is nothing left to
	// attempt: no further calls happen.
	callsAfterDrain := creator.callCount()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, callsAfterDrain, creator.callCount(), "no stitch should have been enqueued to attempt")
	assert.Equal(t, 1, creator.callCount(), "only the original's single attempt, no stitch attempt")
	assert.Equal(t, 0, qd.GetQueueSize())
	assert.Equal(t, qd.maxStitchBacklog, qd.stitchBacklog.Load(), "the backlog must not have grown past its bound")

	reasons := spy.droppedReasons()
	assert.Contains(t, reasons, string(dropReasonMaxAttemptsExhausted))
	assert.Contains(t, reasons, string(dropReasonStitchBacklogExhausted))
	assert.NotContains(t, reasons, string(dropReasonEnqueueFailed), "no enqueue was attempted, so it cannot have failed")
	assert.Empty(t, cb.captured(), "a retryable failure must not end learning for the container")
}

// TestEnforceMaxSize_EvictionEnqueuesStitch is the LRU-eviction counterpart of
// TestQueueDropsUnsplittableProfileOnHTTP413: issue #871 flagged that a hard-capacity eviction
// was also a silent, chain-forking drop, with no replacement ever regenerated. enforceMaxSize
// must repair it the same way dropChunk repairs its own drop paths - and, since MaxQueueSize
// here floors maxStitchBacklog to 1 (see maxStitchBacklogFor), the very next eviction exhausts
// that budget and must fall back to a plain, unrepaired drop rather than growing the queue.
func TestEnforceMaxSize_EvictionEnqueuesStitch(t *testing.T) {
	dir := t.TempDir()
	qd, err := NewQueueData(context.Background(), &alwaysFailingCreator{}, QueueConfig{
		QueueName:       "test-queue",
		QueueDir:        dir,
		MaxQueueSize:    2,
		RetryInterval:   time.Hour, // never started - this test only exercises the enqueue path
		ItemsPerSegment: 10,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qd.Close() })

	evicted := testProfile()
	dropped := testProfile()
	survivor := testProfile()

	require.NoError(t, qd.Enqueue(evicted, "container-id-evicted"))
	require.NoError(t, qd.Enqueue(dropped, "container-id-dropped"))
	// Overflows MaxQueueSize=2: `evicted` is repaired with a stitch (backlog 0 < bound 1), then
	// `dropped` is evicted too, but the backlog is already exhausted, so it is forked with no
	// replacement.
	require.NoError(t, qd.Enqueue(survivor, "container-id-survivor"))

	require.Equal(t, 2, qd.GetQueueSize())
	assert.Equal(t, int64(2), qd.chunksDropped.Load(), "one repaired eviction plus one backlog-exhausted fork")
	assert.Equal(t, int64(1), qd.stitchBacklog.Load(), "the repair stitch is still resident in the queue")

	first, err := qd.queue.Dequeue()
	require.NoError(t, err)
	stitch := first.(*QueuedContainerProfile)

	assert.True(t, stitch.IsStitch)
	assert.Equal(t, "container-id-evicted", stitch.ContainerID)
	assert.NotEqual(t, evicted.Name, stitch.Profile.Name)
	assert.Empty(t, stitch.Profile.Spec.Capabilities, "a stitch carries no size-bearing data")
	assert.Equal(t, evicted.Annotations[helpersv1.PreviousReportTimestampMetadataKey], stitch.Profile.Annotations[helpersv1.PreviousReportTimestampMetadataKey],
		"the stitch must preserve the evicted chunk's chain link")
	assert.Equal(t, evicted.Annotations[helpersv1.ReportTimestampMetadataKey], stitch.Profile.Annotations[helpersv1.ReportTimestampMetadataKey],
		"the stitch must preserve the evicted chunk's chain link")

	second, err := qd.queue.Dequeue()
	require.NoError(t, err)
	assert.Equal(t, survivor.Name, second.(*QueuedContainerProfile).Profile.Name,
		"dropped must have been forked without a replacement, so survivor is next, not a stitch for dropped")
}

// TestEnforceMaxSize_BacklogBoundsRepairCost guards the termination property enforceMaxSize
// depends on: replacing every LRU eviction with a same-count stitch makes no progress toward
// the size limit by itself (see enforceMaxSize's doc comment), so without a cap on the in-flight
// stitch backlog, a single call against a queue full of never-before-stitched real profiles
// would walk through and convert the entire queue before ever making room for the new item that
// triggered it. This drives a burst well past MaxQueueSize into an already-full, all-real queue;
// a regression here would show up as this test hanging (the surrounding go test timeout is the
// tripwire), not as an assertion failure.
func TestEnforceMaxSize_BacklogBoundsRepairCost(t *testing.T) {
	const maxQueueSize = 50

	dir := t.TempDir()
	qd, err := NewQueueData(context.Background(), &alwaysFailingCreator{}, QueueConfig{
		QueueName:       "test-queue",
		QueueDir:        dir,
		MaxQueueSize:    maxQueueSize,
		RetryInterval:   time.Hour,
		ItemsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qd.Close() })

	for i := 0; i < maxQueueSize; i++ {
		require.NoError(t, qd.Enqueue(testProfile(), fmt.Sprintf("container-%d", i)))
	}
	require.Equal(t, maxQueueSize, qd.GetQueueSize())

	for i := 0; i < maxQueueSize*3; i++ {
		require.NoError(t, qd.Enqueue(testProfile(), fmt.Sprintf("container-burst-%d", i)))
		require.LessOrEqual(t, qd.stitchBacklog.Load(), qd.maxStitchBacklog, "stitch backlog must never exceed its bound")
	}

	assert.Equal(t, maxQueueSize, qd.GetQueueSize())
	assert.LessOrEqual(t, qd.stitchBacklog.Load(), qd.maxStitchBacklog)
}

// TestDefaultRetryBudgetOutlastsARestart guards the other side of the bound: the budget
// must be generous enough that a reachable-but-restarting storage does not cause profiles
// to be dropped. A tight bound would trade the infinite-retry bug for silent data loss.
func TestDefaultRetryBudgetOutlastsARestart(t *testing.T) {
	budget := time.Duration(DefaultMaxAttempts) * DefaultRetryInterval

	assert.GreaterOrEqual(t, budget, 15*time.Minute,
		"the default retry budget (%s) must outlast a storage rollout, image pull or node eviction", budget)
}

// TestNewQueueDataDefaultsMaxAttempts pins the default so an unset config cannot restore
// the unbounded-retry behaviour.
func TestNewQueueDataDefaultsMaxAttempts(t *testing.T) {
	for _, configured := range []int{0, -1} {
		qd, err := NewQueueData(context.Background(), &alwaysFailingCreator{}, QueueConfig{
			QueueName:       "test-queue",
			QueueDir:        t.TempDir(),
			ItemsPerSegment: 10,
			MaxAttempts:     configured,
		})
		require.NoError(t, err)
		assert.Equal(t, DefaultMaxAttempts, qd.maxAttempts)
		require.NoError(t, qd.Close())
	}
}

// TestNewQueueDataDefaultsMaxSplitDepth pins the default so an unset config cannot restore
// unbounded splitting.
func TestNewQueueDataDefaultsMaxSplitDepth(t *testing.T) {
	for _, configured := range []int{0, -1} {
		qd, err := NewQueueData(context.Background(), &alwaysFailingCreator{}, QueueConfig{
			QueueName:       "test-queue",
			QueueDir:        t.TempDir(),
			ItemsPerSegment: 10,
			MaxSplitDepth:   configured,
		})
		require.NoError(t, err)
		assert.Equal(t, DefaultMaxSplitDepth, qd.maxSplitDepth)
		require.NoError(t, qd.Close())
	}
}

// spyMetrics wraps MetricsNoop and records split/drop calls, so tests can assert on the
// exact reasons reported without depending on GetQueueStats's internal counters alone.
type spyMetrics struct {
	*metricsmanager.MetricsNoop
	mu      sync.Mutex
	splits  int
	dropped []string
}

func newSpyMetrics() *spyMetrics {
	return &spyMetrics{MetricsNoop: &metricsmanager.MetricsNoop{}}
}

func (s *spyMetrics) ReportContainerProfileSplit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.splits++
}

func (s *spyMetrics) ReportContainerProfileChunkDropped(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropped = append(s.dropped, reason)
}

func (s *spyMetrics) droppedReasons() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dropped...)
}

// TestEnqueueLocked_ReturnsErrQueueNotRunning pins the mechanism requeueSplit's first-half
// failure path depends on: once the queue is no longer running, enqueueLocked refuses rather
// than touching the underlying dque.
func TestEnqueueLocked_ReturnsErrQueueNotRunning(t *testing.T) {
	qd := startQueue(t, &alwaysFailingCreator{}, &recordingCallback{}, QueueConfig{})

	qd.mu.Lock()
	qd.running = false
	qd.mu.Unlock()

	err := qd.enqueueLocked(&QueuedContainerProfile{Profile: testProfile(), ContainerID: "container-id"})
	assert.ErrorIs(t, err, ErrQueueNotRunning)
	assert.Equal(t, 0, qd.GetQueueSize())
}

// TestRequeueSplit_QueueNotRunningDropsBothHalvesAndAttemptsStitch covers the path a previous
// review found untested: when the queue stops running between a chunk being dequeued for
// splitting and its halves being re-enqueued - reachable during Close while processAllItems is
// still mid-flight - requeueSplit must not silently lose the chunk. Both the lost-halves case
// and the stitch-also-failed case must be logged and counted, never swallowed.
func TestRequeueSplit_QueueNotRunningDropsBothHalvesAndAttemptsStitch(t *testing.T) {
	spy := newSpyMetrics()
	qd := startQueue(t, &alwaysFailingCreator{}, &recordingCallback{}, QueueConfig{MetricsManager: spy})

	parent := testProfile()
	parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
	a, b, ok := splitProfile(parent)
	require.True(t, ok, "fixture must be splittable")

	queuedParent := &QueuedContainerProfile{
		Profile:     parent,
		ContainerID: "container-id",
		Attempts:    2,
		SplitDepth:  1,
	}

	qd.mu.Lock()
	qd.running = false
	qd.mu.Unlock()

	qd.requeueSplit(queuedParent, a, b)

	assert.Equal(t, 0, qd.GetQueueSize(), "neither half nor the stitch can land while the queue isn't running")
	assert.Equal(t, int64(2), qd.chunksDropped.Load(),
		"both the lost-halves case and the stitch-also-failed case must be counted")
	assert.Equal(t, []string{string(dropReasonEnqueueFailed), string(dropReasonEnqueueFailed)}, spy.droppedReasons())
}
