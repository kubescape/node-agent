package queue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/joncrlsn/dque"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file"
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
)

// QueuedContainerProfile represents a container profile queued for creation
type QueuedContainerProfile struct {
	Profile     *v1beta1.ContainerProfile `json:"profile"`
	ContainerID string                    `json:"containerID"`
}

// QueuedContainerProfileBuilder creates a new QueuedContainerProfile instance for dque
func QueuedContainerProfileBuilder() interface{} {
	return &QueuedContainerProfile{}
}

// ProfileCreator defines the interface for creating container profiles
type ProfileCreator interface {
	CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error
}

// ErrorCallback defines the interface for handling queue processing errors
type ErrorCallback interface {
	OnQueueError(profile *v1beta1.ContainerProfile, containerID string, err error)
}

// QueueData holds the data and configuration for the queue processing.
type QueueData struct {
	queue         *dque.DQue
	ctx           context.Context
	creator       ProfileCreator
	errorCallback ErrorCallback
	maxQueueSize  int
	retryInterval time.Duration

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
	RetryInterval   time.Duration
	ItemsPerSegment int
	ErrorCallback   ErrorCallback
}

// NewQueueData creates a new QueueData instance with simple LRU behavior
func NewQueueData(ctx context.Context, creator ProfileCreator, config QueueConfig) (*QueueData, error) {
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
	if config.RetryInterval == 0 {
		config.RetryInterval = DefaultRetryInterval
	}
	if config.ItemsPerSegment == 0 {
		config.ItemsPerSegment = ItemsPerSegment
	}

	// Create or open the queue
	queue, err := dque.NewOrOpen(config.QueueName, config.QueueDir, config.ItemsPerSegment, QueuedContainerProfileBuilder)
	if err != nil {
		return nil, fmt.Errorf("failed to create/open queue: %w", err)
	}

	qd := &QueueData{
		queue:         queue,
		ctx:           ctx,
		creator:       creator,
		errorCallback: config.ErrorCallback,
		maxQueueSize:  config.MaxQueueSize,
		retryInterval: config.RetryInterval,
		stopChan:      make(chan struct{}),
		running:       true,
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

	if !qd.running {
		return fmt.Errorf("queue is not running")
	}

	// Create queued profile
	queuedProfile := &QueuedContainerProfile{
		Profile:     profile,
		ContainerID: containerID,
	}

	// Remove oldest items if we're at capacity
	qd.enforceMaxSize()

	// Add new item
	err := qd.queue.Enqueue(queuedProfile)
	if err != nil {
		return fmt.Errorf("failed to enqueue profile: %w", err)
	}

	logger.L().Info("container profile enqueued",
		helpers.String("name", profile.Name),
		helpers.String("namespace", profile.Namespace),
		helpers.Int("queueSize", qd.queue.Size()))

	return nil
}

// enforceMaxSize removes oldest items when queue is at max capacity
func (qd *QueueData) enforceMaxSize() {
	// Remove oldest items if we're at or over capacity
	for qd.queue.Size() >= qd.maxQueueSize {
		_, err := qd.queue.Dequeue()
		if err != nil {
			if err == dque.ErrEmpty {
				break
			}
			logger.L().Error("error removing old item from queue", helpers.Error(err))
			break
		}
		logger.L().Debug("removed oldest item due to size limit")
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
	for i := 0; i < queueSize; i++ {
		// Try to get an item from the queue
		iface, err := qd.queue.Dequeue()
		if err != nil {
			if err == dque.ErrEmpty {
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

		// Attempt to create the profile
		err = qd.creator.CreateContainerProfileDirect(queuedProfile.Profile)
		if err != nil {
			if err.Error() == file.ObjectTooLargeError.Error() || err.Error() == file.ObjectCompletedError.Error() {
				logger.L().Debug("got rejected to create container profile, skipping",
					helpers.String("name", queuedProfile.Profile.Name),
					helpers.Error(err))

				// Call error callback if provided to propagate the error
				if qd.errorCallback != nil {
					qd.errorCallback.OnQueueError(queuedProfile.Profile, queuedProfile.ContainerID, err)
				}
				continue
			}
			logger.L().Debug("failed to create container profile, requeuing",
				helpers.String("name", queuedProfile.Profile.Name),
				helpers.Error(err))

			// Failed - immediately requeue (no delay, no memory storage)
			qd.requeueImmediate(queuedProfile)
		} else {
			logger.L().Info("successfully created container profile",
				helpers.String("name", queuedProfile.Profile.Name),
				helpers.String("namespace", queuedProfile.Profile.Namespace))
		}
	}
}

// requeueImmediate puts a failed item back in the queue immediately
func (qd *QueueData) requeueImmediate(queuedProfile *QueuedContainerProfile) {
	qd.mu.Lock()
	defer qd.mu.Unlock()

	if qd.running {
		// Enforce max size before requeuing
		qd.enforceMaxSize()

		err := qd.queue.Enqueue(queuedProfile)
		if err != nil {
			logger.L().Error("failed to requeue container profile",
				helpers.String("name", queuedProfile.Profile.Name),
				helpers.Error(err))
		}
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
	return map[string]interface{}{
		"size":          qd.GetQueueSize(),
		"maxQueueSize":  qd.maxQueueSize,
		"retryInterval": qd.retryInterval.String(),
		"running":       qd.running,
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
		if err == dque.ErrEmpty {
			break
		}
		if err != nil {
			return fmt.Errorf("error emptying queue: %w", err)
		}
		count++
	}

	logger.L().Info("queue emptied", helpers.Int("itemsRemoved", count))
	return nil
}
