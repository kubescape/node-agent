package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joncrlsn/dque"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	// DefaultQueueName is the default name for the queue.
	DefaultQueueName = "container-profiles-queue"
	// DefaultRetryInterval is the default interval between retries for processing a queue item.
	DefaultRetryInterval = 5 * time.Second
	// DefaultQueueDir is the default directory for the queue.
	DefaultQueueDir = "/profiles"
	// ItemsPerSegment is the number of items per segment in the queue.
	ItemsPerSegment = 100
	// DefaultMaxQueueSize is the default maximum size of the queue
	DefaultMaxQueueSize = 1000
	// DefaultMaxAttempts is the default number of times a single queued profile is retried
	// before it is dropped. Without a bound, a profile that can never be accepted is
	// retried forever, and because the queue is disk-persistent it survives pod restarts.
	//
	// The bound exists to shed permanently-failing items, not to give up on a reachable
	// storage, so it is deliberately generous: at DefaultRetryInterval this is roughly
	// 30 minutes, which comfortably outlasts a storage rollout, image pull or node
	// eviction. Dropping a profile loses data the container has already stopped tracking,
	// so a tight bound would trade the infinite-retry bug for silent loss during an
	// ordinary restart.
	DefaultMaxAttempts = 360
	// stitchBacklogFraction sets maxStitchBacklog to one tenth of a queue's MaxQueueSize (see
	// maxStitchBacklogFor and enforceMaxSize for why that bound exists).
	stitchBacklogFraction = 10
)

// maxStitchBacklogFor computes the in-flight repair-stitch budget for a queue of the given
// capacity. See enforceMaxSize for what the budget is for; it is deliberately small relative to
// maxQueueSize (10%, floor 1) since it trades away chain-repair only under sustained overload,
// not in the common case of one or two evictions between processing ticks.
func maxStitchBacklogFor(maxQueueSize int) int64 {
	if b := int64(maxQueueSize / stitchBacklogFraction); b > 0 {
		return b
	}
	return 1
}

// QueuedContainerProfile represents a container profile queued for creation
type QueuedContainerProfile struct {
	Profile     *v1beta1.ContainerProfile `json:"profile"`
	ContainerID string                    `json:"containerID"`
	// Attempts counts how many times creation of this profile has failed with a
	// retryable error. Items persisted before this field existed decode with Attempts
	// at zero, so they simply get a full budget of retries.
	Attempts int `json:"attempts"`
	// SplitDepth counts how many times this item's lineage has been halved after an HTTP 413.
	// Items persisted before this field existed decode with SplitDepth at zero.
	SplitDepth int `json:"splitDepth"`
	// IsStitch marks a metadata-only chunk emitted in place of a chunk that was dropped or
	// LRU-evicted (see dropChunk and enforceMaxSize) to repair the report chain. A stitch is
	// never split and is never itself stitched - dropping a stitch leaves the chain forked,
	// which is strictly better than an unbounded stitch->drop->stitch loop.
	IsStitch bool `json:"isStitch"`
}

// dropReason labels why a chunk was discarded by dropChunk. The set is closed and every value
// is a compile-time constant, so it is safe as a metric label.
type dropReason string

const (
	// dropReasonUnsplittable: splitProfile refused - floor case, unconstructable chain
	// timestamp, or no byte progress. Collapsed into one reason because all three mean
	// "this chunk cannot be made smaller".
	dropReasonUnsplittable dropReason = "unsplittable"
	// dropReasonDepthExhausted: MaxSplitDepth reached before the chunk became acceptable.
	dropReasonDepthExhausted dropReason = "depth-exhausted"
	// dropReasonStitchRejected: a stitch chunk was itself rejected. Not re-stitched, so this
	// is the one drop that knowingly leaves the report chain forked.
	dropReasonStitchRejected dropReason = "stitch-rejected"
	// dropReasonEnqueueFailed: the replacement stitch could not be enqueued.
	dropReasonEnqueueFailed dropReason = "enqueue-failed"
	// dropReasonMaxAttemptsExhausted: the item's retry budget (MaxAttempts) ran out. The
	// failure may well be container-independent and transient, but by definition it has
	// already been retried for the queue's full retry window (~30 minutes by default)
	// without success - see dropChunk for why it is still repaired rather than silently
	// forking the chain.
	dropReasonMaxAttemptsExhausted dropReason = "max-attempts-exhausted"
	// dropReasonLRUEvicted: the queue was at capacity and this was the oldest item, so
	// enforceMaxSize evicted it to make room and enqueued a stitch in its place.
	dropReasonLRUEvicted dropReason = "lru-evicted"
	// dropReasonLRUBacklogExhausted: same as dropReasonLRUEvicted, but the in-flight stitch
	// backlog (see maxStitchBacklog) was already at its bound, so no replacement was
	// enqueued and this eviction forks the chain.
	dropReasonLRUBacklogExhausted dropReason = "lru-backlog-exhausted"
)

// ErrQueueNotRunning is returned by enqueueLocked once the queue has been closed.
var ErrQueueNotRunning = errors.New("queue is not running")

// QueuedContainerProfileBuilder creates a new QueuedContainerProfile instance for dque
func QueuedContainerProfileBuilder() interface{} {
	return &QueuedContainerProfile{}
}

// ErrorCallback defines the interface for handling queue processing errors
type ErrorCallback interface {
	OnQueueError(profile *v1beta1.ContainerProfile, containerID string, err error)
}

// QueueData holds the data and configuration for the queue processing.
type QueueData struct {
	queue         *dque.DQue
	ctx           context.Context
	creator       storage.ProfileCreator
	errorCallback ErrorCallback
	maxQueueSize  int
	maxAttempts   int
	maxSplitDepth int
	retryInterval time.Duration
	metrics       metricsmanager.MetricsManager

	// maxStitchBacklog bounds stitchBacklog - see enforceMaxSize for why that bound has to
	// exist at all. Fixed at construction time from maxQueueSize.
	maxStitchBacklog int64

	// Written by the queue processor goroutine and read by GetQueueStats, so they carry
	// their own synchronization rather than widening qd.mu.
	splits        atomic.Int64
	chunksDropped atomic.Int64
	// stitchBacklog counts IsStitch items currently resident in the queue (enqueued but not
	// yet dequeued for processing or eviction). Every enqueue/dequeue of the underlying dque
	// funnels through enqueueLocked/enqueueStitchNoEvict and processAllItems/enforceMaxSize
	// respectively, which keep this in step; see enforceMaxSize for what it's used for.
	//
	// It starts at zero on every process start and is never reconciled against stitches the
	// disk queue may already hold from a prior run (dque has no cheap way to count a
	// predicate over its contents without draining it). This can only ever under-count, so the
	// worst case is enforceMaxSize allowing a brief burst of extra replacements right after a
	// restart before it settles - never an incorrect refusal to repair a chain.
	stitchBacklog atomic.Int64

	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	running  bool
}

// QueueConfig holds configuration for the queue
type QueueConfig struct {
	QueueName       string
	QueueDir        string
	MaxQueueSize    int
	MaxAttempts     int
	MaxSplitDepth   int
	RetryInterval   time.Duration
	ItemsPerSegment int
	ErrorCallback   ErrorCallback
	MetricsManager  metricsmanager.MetricsManager
}

// NewQueueData creates a new QueueData instance with simple LRU behavior
func NewQueueData(ctx context.Context, creator storage.ProfileCreator, config QueueConfig) (*QueueData, error) {
	// Set defaults
	if config.QueueName == "" {
		config.QueueName = DefaultQueueName
	}
	if config.QueueDir == "" {
		config.QueueDir = DefaultQueueDir
	}
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = DefaultMaxQueueSize
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = DefaultMaxAttempts
	}
	if config.MaxSplitDepth <= 0 {
		config.MaxSplitDepth = DefaultMaxSplitDepth
	}
	if config.MetricsManager == nil {
		config.MetricsManager = &metricsmanager.MetricsNoop{}
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = DefaultRetryInterval
	}
	if config.ItemsPerSegment == 0 {
		config.ItemsPerSegment = ItemsPerSegment
	}

	// Create or open the queue
	queue, err := dque.NewOrOpen(config.QueueName, config.QueueDir, config.ItemsPerSegment, QueuedContainerProfileBuilder)
	if err != nil {
		var corruptedError dque.ErrCorruptedSegment
		if errors.As(err, &corruptedError) {
			logger.L().Info("queue corrupted, deleting and recreating", helpers.Error(err))

			// Delete the specific queue's data directory.
			queueDataPath := filepath.Join(config.QueueDir, config.QueueName)
			if err := os.RemoveAll(queueDataPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted queue directory %s: %w", queueDataPath, err)
			}

			// Try to create the queue again.
			queue, err = dque.NewOrOpen(config.QueueName, config.QueueDir, config.ItemsPerSegment, QueuedContainerProfileBuilder)
			if err != nil {
				return nil, fmt.Errorf("failed to create queue after cleaning corruption: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to create/open queue: %w", err)
		}
	}
	if err := queue.TurboOn(); err != nil {
		logger.L().Error("failed to enable turbo mode", helpers.Error(err))
	}

	qd := &QueueData{
		queue:            queue,
		ctx:              ctx,
		creator:          creator,
		errorCallback:    config.ErrorCallback,
		maxQueueSize:     config.MaxQueueSize,
		maxAttempts:      config.MaxAttempts,
		maxSplitDepth:    config.MaxSplitDepth,
		maxStitchBacklog: maxStitchBacklogFor(config.MaxQueueSize),
		retryInterval:    config.RetryInterval,
		metrics:          config.MetricsManager,
		stopChan:         make(chan struct{}),
		running:          true,
	}

	// Remove old items if queue is over capacity on startup
	qd.enforceMaxSize()

	return qd, nil
}

// Start begins processing the queue
func (qd *QueueData) Start() {
	qd.mu.Lock()
	defer qd.mu.Unlock()

	if qd.running {
		qd.wg.Add(1)
		go qd.processQueue()

		logger.L().Info("Container profile queue started",
			helpers.Int("maxQueueSize", qd.maxQueueSize),
			helpers.Int("currentSize", qd.queue.Size()))
	}
}

// Enqueue adds a new container profile to the queue with LRU eviction
func (qd *QueueData) Enqueue(profile *v1beta1.ContainerProfile, containerID string) error {
	qd.mu.Lock()
	defer qd.mu.Unlock()

	if err := qd.enqueueLocked(&QueuedContainerProfile{
		Profile:     profile,
		ContainerID: containerID,
	}); err != nil {
		return err
	}

	logger.L().Debug("container profile enqueued",
		helpers.String("name", profile.Name),
		helpers.String("namespace", profile.Namespace),
		helpers.Int("queueSize", qd.queue.Size()))

	return nil
}

// enqueueLocked adds item to the queue, evicting the oldest items first.
// Callers must hold qd.mu.
func (qd *QueueData) enqueueLocked(item *QueuedContainerProfile) error {
	if !qd.running {
		return ErrQueueNotRunning
	}

	// Remove oldest items if we're at capacity
	qd.enforceMaxSize()

	if err := qd.queue.Enqueue(item); err != nil {
		return fmt.Errorf("failed to enqueue profile: %w", err)
	}
	if item.IsStitch {
		qd.stitchBacklog.Add(1)
	}

	return nil
}

// enqueueStitchNoEvict adds a repair stitch directly to the tail without invoking
// enforceMaxSize.
//
// It exists only for enforceMaxSize's own use: enforceMaxSize always runs under qd.mu (it's
// only ever called from enqueueLocked, whose callers must already hold the lock), so routing
// its replacement stitch back through enqueueLocked - which calls enforceMaxSize itself - would
// re-enter the very loop this is called from. Every other stitch insertion (dropChunk,
// requeueSplit) goes through enqueueLocked as normal, so capacity is enforced for them exactly
// like any other enqueue.
func (qd *QueueData) enqueueStitchNoEvict(item *QueuedContainerProfile) error {
	if err := qd.queue.Enqueue(item); err != nil {
		return err
	}
	qd.stitchBacklog.Add(1)
	return nil
}

// newStitchFor builds the metadata-only replacement enqueued in place of dropped, so the
// container's report-timestamp chain (see stitchChunk) survives the drop. SplitDepth is set to
// qd.maxSplitDepth so a stitch that later fails and needs its own drop reason goes straight to
// dropReasonStitchRejected rather than treating a chunk that has nothing left to give as
// splittable.
func (qd *QueueData) newStitchFor(dropped *QueuedContainerProfile) *QueuedContainerProfile {
	return &QueuedContainerProfile{
		Profile:     stitchChunk(dropped.Profile),
		ContainerID: dropped.ContainerID,
		Attempts:    dropped.Attempts,
		SplitDepth:  qd.maxSplitDepth,
		IsStitch:    true,
	}
}

// enforceMaxSize evicts oldest items while the queue is at or over capacity.
//
// A plain eviction silently forks the evicted container's report-timestamp chain: storage can
// only complete a profile whose consolidated chain traces back to the container's first report,
// so one missing link hangs that container in Learning forever with no field-visible symptom
// (issue #871). So an item evicted here that isn't already a stitch is replaced with one at the
// tail via enqueueStitchNoEvict, the same repair dropChunk performs for its own drop paths.
//
// That replacement makes no net progress toward the size limit by itself - one item out, one
// (smaller, but equally counted) item back in - so the loop condition is rechecked and eviction
// continues onto the next-oldest item. Real progress happens only once the head is already a
// stitch (evicted for good, never replaced - same rule as dropChunk) or once the in-flight
// stitch backlog is exhausted, at which point this falls back to a plain drop that forks the
// chain. Without that bound, a queue that starts out entirely full of real, never-before-
// stitched profiles would have a single call here walk through and convert the whole queue
// before ever making room for the new item that triggered it.
func (qd *QueueData) enforceMaxSize() {
	for qd.queue.Size() >= qd.maxQueueSize {
		iface, err := qd.queue.Dequeue()
		if err != nil {
			if errors.Is(err, dque.ErrEmpty) {
				break
			}
			logger.L().Error("error removing old item from queue", helpers.Error(err))
			break
		}

		evicted, ok := iface.(*QueuedContainerProfile)
		if !ok {
			logger.L().Error("evicted item is not a QueuedContainerProfile",
				helpers.String("type", fmt.Sprintf("%T", iface)))
			continue
		}

		if evicted.IsStitch {
			qd.stitchBacklog.Add(-1)
			logger.L().Debug("removed oldest item due to size limit, item was already a stitch")
			continue
		}

		logger.L().Debug("removed oldest item due to size limit",
			helpers.String("name", evicted.Profile.Name),
			helpers.String("namespace", evicted.Profile.Namespace))

		if qd.stitchBacklog.Load() >= qd.maxStitchBacklog {
			qd.chunksDropped.Add(1)
			qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonLRUBacklogExhausted))

			logger.L().Warning("evicted container profile chunk to enforce queue size, stitch backlog is exhausted so its report chain is now forked",
				helpers.String("name", evicted.Profile.Name),
				helpers.String("namespace", evicted.Profile.Namespace),
				helpers.String("containerID", evicted.ContainerID))
			continue
		}

		qd.chunksDropped.Add(1)
		qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonLRUEvicted))

		stitch := qd.newStitchFor(evicted)
		if err := qd.enqueueStitchNoEvict(stitch); err != nil {
			logger.L().Warning("failed to enqueue replacement stitch chunk after LRU eviction, the report chain is now forked",
				helpers.String("name", stitch.Profile.Name),
				helpers.String("namespace", stitch.Profile.Namespace),
				helpers.String("containerID", evicted.ContainerID),
				helpers.Error(err))

			qd.chunksDropped.Add(1)
			qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonEnqueueFailed))
			continue
		}

		logger.L().Warning("evicted container profile chunk to enforce queue size, enqueued a stitch to preserve its report chain",
			helpers.String("name", evicted.Profile.Name),
			helpers.String("namespace", evicted.Profile.Namespace),
			helpers.String("containerID", evicted.ContainerID))
	}
}

// processQueue runs in a goroutine and processes items from the disk queue
func (qd *QueueData) processQueue() {
	defer qd.wg.Done()

	logger.L().Info("queue processor started")

	ticker := time.NewTicker(qd.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-qd.stopChan:
			logger.L().Info("queue processor stopping...")
			return
		case <-qd.ctx.Done():
			logger.L().Info("queue processor stopping due to context cancellation...")
			return
		case <-ticker.C:
			qd.processAllItems()
		}
	}
}

// processAllItems attempts to process all items in the queue
func (qd *QueueData) processAllItems() {
	queueSize := qd.queue.Size()
	if queueSize == 0 {
		return
	}

	logger.L().Debug("processing queue", helpers.Int("size", queueSize))

	// Process each item in the queue
processLoop:
	for i := 0; i < queueSize; i++ {
		// Try to get an item from the queue
		iface, err := qd.queue.Dequeue()
		if err != nil {
			if errors.Is(err, dque.ErrEmpty) {
				// Queue is empty, we're done
				break
			}
			logger.L().Error("error dequeuing item", helpers.Error(err))
			break
		}

		// Type assert to QueuedContainerProfile
		queuedProfile, ok := iface.(*QueuedContainerProfile)
		if !ok {
			logger.L().Error("dequeued item is not a QueuedContainerProfile",
				helpers.String("type", fmt.Sprintf("%T", iface)))
			continue
		}
		if queuedProfile.IsStitch {
			// It has left the queue for processing; enforceMaxSize's backlog bound (see its
			// doc comment) only needs to track stitches still resident in the queue. If this
			// attempt fails and the item is requeued or re-dropped-and-replaced below, that
			// path re-enqueues through enqueueLocked/enqueueStitchNoEvict, which increments
			// the backlog again.
			qd.stitchBacklog.Add(-1)
		}

		// Attempt to create the profile
		err = qd.creator.CreateContainerProfileDirect(queuedProfile.Profile)
		if err != nil {
			// An explicit switch, so that a future fourth failureKind cannot silently fall
			// through to the retryable branch.
			kind, reported := classifyFailure(err)
			switch kind {
			case failureTerminal:
				logger.L().Debug("got rejected to create container profile, skipping",
					helpers.String("name", queuedProfile.Profile.Name),
					helpers.Error(err))

				// Call error callback if provided to propagate the error. The sentinel is
				// reported rather than err itself, so that the manager can map it onto the
				// right terminal container status even when the transport lost the sentinel.
				if qd.errorCallback != nil {
					qd.errorCallback.OnQueueError(queuedProfile.Profile, queuedProfile.ContainerID, reported)
				}

			case failureSplit:
				// A bare 413 rejects this one delta for its size; it says nothing about the
				// container, so learning continues and only the chunk is shed.
				switch {
				case queuedProfile.IsStitch:
					qd.dropChunk(queuedProfile, dropReasonStitchRejected)
				case queuedProfile.SplitDepth >= qd.maxSplitDepth:
					qd.dropChunk(queuedProfile, dropReasonDepthExhausted)
				default:
					a, b, ok := splitProfile(queuedProfile.Profile)
					if !ok {
						qd.dropChunk(queuedProfile, dropReasonUnsplittable)
						continue
					}

					logger.L().Debug("splitting container profile rejected with 413",
						helpers.String("name", queuedProfile.Profile.Name),
						helpers.String("namespace", queuedProfile.Profile.Namespace),
						helpers.Int("splitDepth", queuedProfile.SplitDepth),
						helpers.Int("elements", countPartitionableElements(&queuedProfile.Profile.Spec)),
						helpers.Int("bytes", serializedSize(queuedProfile.Profile)))

					qd.splits.Add(1)
					qd.metrics.ReportContainerProfileSplit()
					qd.requeueSplit(queuedProfile, a, b)
				}

			case failureRetryable:
				// Bound the number of retries so that an item which never succeeds cannot
				// occupy the queue indefinitely: requeuing appends to the tail while
				// enforceMaxSize evicts from the head, so an unbounded retry would push out
				// newer profiles that could have been saved.
				queuedProfile.Attempts++
				if queuedProfile.Attempts >= qd.maxAttempts {
					qd.dropChunk(queuedProfile, dropReasonMaxAttemptsExhausted)
					continue
				}

				logger.L().Debug("failed to create container profile, requeuing",
					helpers.String("name", queuedProfile.Profile.Name),
					helpers.Int("attempts", queuedProfile.Attempts),
					helpers.Error(err))

				qd.requeueImmediate(queuedProfile)

				// Check for "too many requests" error
				if strings.Contains(err.Error(), "the server has received too many requests and has asked us to try again later") {
					logger.L().Debug("server overloaded, breaking processing loop and waiting for next interval",
						helpers.String("name", queuedProfile.Profile.Name),
						helpers.Error(err))

					break processLoop
				}
			}

		} else {
			logger.L().Debug("successfully created container profile",
				helpers.String("name", queuedProfile.Profile.Name),
				helpers.String("namespace", queuedProfile.Profile.Namespace))
		}
	}
}

// requeueImmediate puts a failed item back in the queue immediately
func (qd *QueueData) requeueImmediate(queuedProfile *QueuedContainerProfile) {
	qd.mu.Lock()
	defer qd.mu.Unlock()

	if err := qd.enqueueLocked(queuedProfile); err != nil {
		logger.L().Debug("failed to requeue container profile",
			helpers.String("name", queuedProfile.Profile.Name),
			helpers.Error(err))
	}
}

// requeueSplit enqueues both halves of a split chunk under a single lock acquisition, so the
// two halves are never separated by a concurrent Enqueue or by an intervening eviction sweep.
//
// Both halves inherit parent.Attempts, take SplitDepth = parent.SplitDepth+1, and are explicitly
// IsStitch = false (the zero value - stated because a half must always remain splittable).
//
// Callers must NOT hold qd.mu.
func (qd *QueueData) requeueSplit(parent *QueuedContainerProfile, a, b *v1beta1.ContainerProfile) {
	half := func(profile *v1beta1.ContainerProfile) *QueuedContainerProfile {
		return &QueuedContainerProfile{
			Profile:     profile,
			ContainerID: parent.ContainerID,
			Attempts:    parent.Attempts,
			SplitDepth:  parent.SplitDepth + 1,
			IsStitch:    false,
		}
	}

	qd.mu.Lock()
	defer qd.mu.Unlock()

	if err := qd.enqueueLocked(half(a)); err != nil {
		// The parent was already dequeued, so neither half reaches the queue: this is a
		// total loss of the chunk, not just a fork, and must be at least as loud as the
		// second-half case below. Unlike that case, nothing of the parent's data survives
		// to carry its (previousReportTimestamp, reportTimestamp] interval forward, so the
		// stitch is built from parent.Profile itself - that interval is exactly what needs
		// repairing since it never reached the queue in any form.
		logger.L().Warning("failed to enqueue the first half of a split container profile, both halves are lost",
			helpers.String("name", a.Name),
			helpers.String("namespace", a.Namespace),
			helpers.String("containerID", parent.ContainerID),
			helpers.Error(err))

		qd.chunksDropped.Add(1)
		qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonEnqueueFailed))

		stitch := qd.newStitchFor(parent)
		if stitchErr := qd.enqueueLocked(stitch); stitchErr != nil {
			logger.L().Warning("failed to enqueue replacement stitch chunk after a lost split, the report chain is now forked",
				helpers.String("name", stitch.Profile.Name),
				helpers.String("namespace", stitch.Profile.Namespace),
				helpers.String("containerID", parent.ContainerID),
				helpers.Error(stitchErr))

			qd.chunksDropped.Add(1)
			qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonEnqueueFailed))
		}
		return
	}

	if err := qd.enqueueLocked(half(b)); err != nil {
		// Exactly one half of a pair survived, which forks the container's report chain.
		logger.L().Warning("failed to enqueue the second half of a split container profile, its report chain is now forked",
			helpers.String("name", b.Name),
			helpers.String("namespace", b.Namespace),
			helpers.String("containerID", parent.ContainerID),
			helpers.Error(err))

		qd.chunksDropped.Add(1)
		qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonEnqueueFailed))
	}
}

// dropChunk discards a queued chunk that cannot be delivered as-is: because it was rejected for
// its size and cannot be split further (failureSplit), or because it exhausted its retry budget
// without ever succeeding (failureRetryable, dropReasonMaxAttemptsExhausted).
//
// It deliberately does NOT call errorCallback.OnQueueError: that path ends learning for the
// whole container. A single delta failing to fit, or timing out its retry budget, says nothing
// about whether the container is learnable - losing one delta is strictly better than losing
// every future delta.
//
// It enqueues a stitch chunk in the dropped chunk's place so the report chain stays linear
// (see chainHalves); without it, dropping the chunk forks the chain and hangs the profile in
// Learning. A dropped stitch is never re-stitched: that would loop forever, since neither drop
// path touches Attempts.
//
// Callers must NOT hold qd.mu.
func (qd *QueueData) dropChunk(dropped *QueuedContainerProfile, reason dropReason) {
	logger.L().Warning("dropping container profile chunk",
		helpers.String("name", dropped.Profile.Name),
		helpers.String("namespace", dropped.Profile.Namespace),
		helpers.String("containerID", dropped.ContainerID),
		helpers.String("reason", string(reason)),
		helpers.Int("attempts", dropped.Attempts),
		helpers.Int("splitDepth", dropped.SplitDepth),
		helpers.Int("bytes", serializedSize(dropped.Profile)))

	qd.chunksDropped.Add(1)
	qd.metrics.ReportContainerProfileChunkDropped(string(reason))

	if dropped.IsStitch {
		return
	}

	stitch := qd.newStitchFor(dropped)

	qd.mu.Lock()
	err := qd.enqueueLocked(stitch)
	qd.mu.Unlock()

	if err != nil {
		logger.L().Warning("failed to enqueue replacement stitch chunk, the report chain is now forked",
			helpers.String("name", stitch.Profile.Name),
			helpers.String("namespace", stitch.Profile.Namespace),
			helpers.String("containerID", dropped.ContainerID),
			helpers.Error(err))

		qd.chunksDropped.Add(1)
		qd.metrics.ReportContainerProfileChunkDropped(string(dropReasonEnqueueFailed))
	}
}

// GetQueueSize returns the current number of items in the queue
func (qd *QueueData) GetQueueSize() int {
	if qd.queue == nil {
		return 0
	}
	return qd.queue.Size()
}

// GetQueueStats returns basic statistics about the queue
func (qd *QueueData) GetQueueStats() map[string]interface{} {
	// running is written under qd.mu by Close, so it must be read under it too.
	qd.mu.Lock()
	running := qd.running
	size := qd.GetQueueSize()
	qd.mu.Unlock()

	return map[string]interface{}{
		"size":             size,
		"maxQueueSize":     qd.maxQueueSize,
		"maxSplitDepth":    qd.maxSplitDepth,
		"retryInterval":    qd.retryInterval.String(),
		"running":          running,
		"splits":           qd.splits.Load(),
		"chunksDropped":    qd.chunksDropped.Load(),
		"stitchBacklog":    qd.stitchBacklog.Load(),
		"maxStitchBacklog": qd.maxStitchBacklog,
	}
}

// Close gracefully shuts down the queue
func (qd *QueueData) Close() error {
	logger.L().Info("shutting down queue...")

	qd.mu.Lock()
	qd.running = false
	qd.mu.Unlock()

	// Stop the queue processor
	close(qd.stopChan)
	qd.wg.Wait()

	// Close the disk queue
	if qd.queue != nil {
		qd.queue.Close()
		logger.L().Info("queue shut down", helpers.Int("finalQueueSize", qd.queue.Size()))
	}

	return nil
}

// EmptyQueue clears all items from the queue
func (qd *QueueData) EmptyQueue() error {
	qd.mu.Lock()
	defer qd.mu.Unlock()

	logger.L().Info("emptying queue...")

	count := 0
	for {
		_, err := qd.queue.Dequeue()
		if errors.Is(err, dque.ErrEmpty) {
			break
		}
		if err != nil {
			return fmt.Errorf("error emptying queue: %w", err)
		}
		count++
	}
	qd.stitchBacklog.Store(0)

	logger.L().Info("queue emptied", helpers.Int("itemsRemoved", count))
	return nil
}
