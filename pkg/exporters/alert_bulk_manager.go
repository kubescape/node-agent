package exporters

import (
	"context"
	"math"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

// containerBulk holds alerts for a single container
type containerBulk struct {
	sync.Mutex
	containerID     string
	alerts          []apitypes.RuntimeAlert
	processMap      map[uint32]*apitypes.Process // Incremental map for O(1) lookup
	rootProcess     *apitypes.Process            // Root of merged tree
	cloudServices   []string
	firstAlertTime  time.Time
	maxSize         int
	timeoutDuration time.Duration
}

// shouldFlush returns true if the bulk should be flushed based on size or timeout
func (cb *containerBulk) shouldFlush() bool {
	cb.Lock()
	defer cb.Unlock()

	// Check size limit
	if len(cb.alerts) >= cb.maxSize {
		return true
	}

	// Check timeout
	if !cb.firstAlertTime.IsZero() && time.Since(cb.firstAlertTime) >= cb.timeoutDuration {
		return true
	}

	return false
}

// addAlert adds an alert to the bulk and merges its process chain
// Optimized for chain-structured process trees (container init -> parent -> ... -> offending process)
func (cb *containerBulk) addAlert(alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) {
	cb.Lock()
	defer cb.Unlock()

	// Add alert (maintains temporal order since alerts are added sequentially)
	cb.alerts = append(cb.alerts, alert)

	// Set first alert time if this is the first alert
	if cb.firstAlertTime.IsZero() {
		cb.firstAlertTime = time.Now()
	}

	// Merge process chain (ProcessTree struct wraps Process in .ProcessTree field)
	if processTree.ProcessTree.PID != 0 {
		cb.mergeProcessChain(&processTree.ProcessTree)
	}

	// Merge cloud services
	cb.cloudServices = utils.MergeCloudServices(cb.cloudServices, cloudServices)
}

// mergeProcessChain merges a chain-structured process tree into the accumulated tree
// This is optimized for chains: ContainerInit -> Parent1 -> ... -> OffendingProcess
// Complexity: O(k) where k is chain length, vs O(n) for full tree merge
func (cb *containerBulk) mergeProcessChain(chain *apitypes.Process) {
	if chain == nil || chain.PID == 0 {
		return
	}

	// Lazy initialization
	if cb.processMap == nil {
		cb.processMap = make(map[uint32]*apitypes.Process)
	}

	// Ensure chain uses map structure
	chain.MigrateToMap()

	// Flatten chain into ordered list (root-first)
	chainList := utils.FlattenChainToList(chain)

	// Walk chain from root to leaf
	for _, sourceNode := range chainList {
		existing, exists := cb.processMap[sourceNode.PID]

		if exists {
			// Process already in tree - enrich with any new information
			utils.EnrichProcess(existing, sourceNode)
		} else {
			// New process - create and link
			newNode := utils.CopyProcess(sourceNode)
			cb.processMap[newNode.PID] = newNode

			// Set first process as initial root
			if cb.rootProcess == nil {
				cb.rootProcess = newNode
			}

			// Link to parent if parent exists in tree
			if newNode.PPID != 0 {
				if parent, ok := cb.processMap[newNode.PPID]; ok {
					if parent.ChildrenMap == nil {
						parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
					}
					parent.ChildrenMap[apitypes.CommPID{PID: newNode.PID}] = newNode
				} else {
					// Parent doesn't exist in tree - this is a new root
					// We need to handle multiple roots by creating a synthetic parent
					if newNode.PPID == 0 || newNode != cb.rootProcess {
						cb.attachToSyntheticRoot(newNode)
					}
				}
			} else {
				// PPID == 0 means this is a root process
				// If we already have a different root, attach both to synthetic root
				if cb.rootProcess.PID != newNode.PID {
					cb.attachToSyntheticRoot(newNode)
				}
			}
		}
	}
}

// attachToSyntheticRoot creates a synthetic root (PID 1) to hold multiple independent process trees
func (cb *containerBulk) attachToSyntheticRoot(newRoot *apitypes.Process) {
	const syntheticRootPID = 1

	// Check if we need to convert existing root to use synthetic parent
	if cb.rootProcess.PID != syntheticRootPID {
		// Create synthetic root if it doesn't exist
		if _, exists := cb.processMap[syntheticRootPID]; !exists {
			syntheticRoot := &apitypes.Process{
				PID:         syntheticRootPID,
				PPID:        0,
				Comm:        "container-root",
				ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
			}
			cb.processMap[syntheticRootPID] = syntheticRoot

			// Attach current root to synthetic root
			syntheticRoot.ChildrenMap[apitypes.CommPID{PID: cb.rootProcess.PID}] = cb.rootProcess

			// Update root reference
			cb.rootProcess = syntheticRoot
		}
	}

	// Attach new root to synthetic root
	cb.rootProcess.ChildrenMap[apitypes.CommPID{PID: newRoot.PID}] = newRoot
}

// flush returns the bulk data and resets the bulk
func (cb *containerBulk) flush() ([]apitypes.RuntimeAlert, apitypes.ProcessTree, []string) {
	cb.Lock()
	defer cb.Unlock()

	alerts := cb.alerts

	// Build result from root process
	processTree := apitypes.ProcessTree{}
	if cb.rootProcess != nil {
		processTree.ProcessTree = *cb.rootProcess
	}

	cloudServices := cb.cloudServices

	// Clear state (bulk is removed from map after flush, so reset is for safety)
	cb.alerts = nil
	cb.processMap = nil
	cb.rootProcess = nil
	cb.cloudServices = nil
	cb.firstAlertTime = time.Time{}

	return alerts, processTree, cloudServices
}

// bulkQueueItem represents a bulk waiting to be sent
type bulkQueueItem struct {
	containerID   string
	alerts        []apitypes.RuntimeAlert
	processTree   apitypes.ProcessTree
	cloudServices []string
	retryCount    int
	enqueuedAt    time.Time
	lastAttemptAt time.Time
}

// AlertBulkManager manages alert bulks per container
type AlertBulkManager struct {
	sync.RWMutex
	bulks               map[string]*containerBulk
	bulkMaxAlerts       int
	bulkTimeoutDuration time.Duration
	flushInterval       time.Duration

	// Send queue fields
	sendQueue       chan *bulkQueueItem
	sendQueueSize   int
	maxRetries      int
	retryBaseDelay  time.Duration
	retryMaxDelay   time.Duration
	sendWorkerCount int

	sendFunc func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewAlertBulkManager creates a new alert bulk manager
func NewAlertBulkManager(
	bulkMaxAlerts int,
	bulkTimeoutSeconds int,
	sendQueueSize int,
	maxRetries int,
	retryBaseDelayMs int,
	retryMaxDelayMs int,
	sendFunc func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error,
) *AlertBulkManager {
	// Set defaults
	if sendQueueSize == 0 {
		sendQueueSize = 1000
	}
	if maxRetries == 0 {
		maxRetries = 3
	}
	if retryBaseDelayMs == 0 {
		retryBaseDelayMs = 1000
	}
	if retryMaxDelayMs == 0 {
		retryMaxDelayMs = 30000
	}

	return &AlertBulkManager{
		bulks:               make(map[string]*containerBulk),
		bulkMaxAlerts:       bulkMaxAlerts,
		bulkTimeoutDuration: time.Duration(bulkTimeoutSeconds) * time.Second,
		flushInterval:       1 * time.Second, // Fixed 1 second interval
		sendQueue:           make(chan *bulkQueueItem, sendQueueSize),
		sendQueueSize:       sendQueueSize,
		maxRetries:          maxRetries,
		retryBaseDelay:      time.Duration(retryBaseDelayMs) * time.Millisecond,
		retryMaxDelay:       time.Duration(retryMaxDelayMs) * time.Millisecond,
		sendWorkerCount:     1, // Default to 1 for FIFO ordering
		sendFunc:            sendFunc,
		stopChan:            make(chan struct{}),
	}
}

// Start begins the background flush goroutine and send workers
func (abm *AlertBulkManager) Start() {
	// Start background flush goroutine
	abm.wg.Add(1)
	go abm.backgroundFlush()

	// Start send worker goroutines
	for i := 0; i < abm.sendWorkerCount; i++ {
		abm.wg.Add(1)
		go abm.sendWorker()
	}

	logger.L().Info("Alert bulk manager started")
}

// Stop stops the background flush goroutine and flushes all pending bulks
func (abm *AlertBulkManager) Stop() {
	// Signal all goroutines to stop
	close(abm.stopChan)

	// Wait for background flush and send workers
	abm.wg.Wait()

	// Note: stopChan close will trigger drainSendQueue() in workers

	logger.L().Info("Alert bulk manager stopped")
}

// AddAlert adds an alert to the appropriate container bulk
func (abm *AlertBulkManager) AddAlert(alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) {
	containerID := alert.RuntimeAlertK8sDetails.ContainerID
	if containerID == "" {
		logger.L().Warning("AlertBulkManager.AddAlert - containerID is empty, cannot add to bulk")
		return
	}

	abm.Lock()
	// Get or create bulk for this container
	bulk, exists := abm.bulks[containerID]
	if !exists {
		bulk = &containerBulk{
			containerID:     containerID,
			alerts:          make([]apitypes.RuntimeAlert, 0, abm.bulkMaxAlerts),
			cloudServices:   make([]string, 0),
			maxSize:         abm.bulkMaxAlerts,
			timeoutDuration: abm.bulkTimeoutDuration,
		}
		abm.bulks[containerID] = bulk
		logger.L().Debug("AlertBulkManager - created new bulk", helpers.String("containerID", containerID))
	}

	// Add alert to bulk (while holding lock)
	bulk.addAlert(alert, processTree, cloudServices)

	// Check if bulk should be flushed immediately (size limit reached)
	// If so, remove it from the map atomically while we have the lock
	var bulkToFlush *containerBulk
	if bulk.shouldFlush() {
		bulkToFlush = bulk
		delete(abm.bulks, containerID)
	}
	abm.Unlock()

	// Flush outside the lock to avoid holding lock during enqueue
	if bulkToFlush != nil {
		abm.sendBulk(containerID, bulkToFlush)
	}
}

// FlushContainer immediately flushes and removes the bulk for a specific container
// This should be called when a container stops
func (abm *AlertBulkManager) FlushContainer(containerID string) {
	abm.flushBulk(containerID)
}

// FlushAll flushes all pending bulks
func (abm *AlertBulkManager) FlushAll() {
	abm.RLock()
	containerIDs := make([]string, 0, len(abm.bulks))
	for containerID := range abm.bulks {
		containerIDs = append(containerIDs, containerID)
	}
	abm.RUnlock()

	for _, containerID := range containerIDs {
		abm.flushBulk(containerID)
	}
}

// flushBulk flushes and removes a specific container bulk
func (abm *AlertBulkManager) flushBulk(containerID string) {
	abm.Lock()
	bulk, exists := abm.bulks[containerID]
	if !exists {
		abm.Unlock()
		return
	}
	// Remove bulk from map atomically
	delete(abm.bulks, containerID)
	abm.Unlock()

	// Flush outside the lock
	abm.sendBulk(containerID, bulk)
}

// sendBulk handles enqueueing a bulk for sending
func (abm *AlertBulkManager) sendBulk(containerID string, bulk *containerBulk) {
	alerts, processTree, cloudServices := bulk.flush()

	if len(alerts) == 0 {
		return
	}

	item := &bulkQueueItem{
		containerID:   containerID,
		alerts:        alerts,
		processTree:   processTree,
		cloudServices: cloudServices,
		retryCount:    0,
		enqueuedAt:    time.Now(),
	}

	// Try to enqueue with timeout to prevent blocking
	select {
	case abm.sendQueue <- item:
		logger.L().Debug("Bulk enqueued for sending",
			helpers.String("containerID", containerID),
			helpers.Int("alertCount", len(alerts)))

	case <-time.After(1 * time.Second):
		// Queue full and timeout - drop bulk
		logger.L().Error("Failed to enqueue bulk, queue full or blocked",
			helpers.String("containerID", containerID),
			helpers.Int("alertCount", len(alerts)),
			helpers.Int("queueSize", abm.sendQueueSize))
	}
}

// sendWorker processes items from the send queue
func (abm *AlertBulkManager) sendWorker() {
	defer abm.wg.Done()

	for {
		select {
		case item := <-abm.sendQueue:
			abm.processSendQueueItem(item)
		case <-abm.stopChan:
			// Drain remaining items from queue
			abm.drainSendQueue()
			return
		}
	}
}

// processSendQueueItem attempts to send a bulk with retry logic
// Retries are performed in-place to maintain FIFO ordering
func (abm *AlertBulkManager) processSendQueueItem(item *bulkQueueItem) {
	for {
		// Attempt send
		err := abm.sendFunc(item.containerID, item.alerts, item.processTree, item.cloudServices)

		if err == nil {
			// Success
			logger.L().Debug("Successfully sent bulk",
				helpers.String("containerID", item.containerID),
				helpers.Int("alertCount", len(item.alerts)),
				helpers.Int("retryCount", item.retryCount))
			return
		}

		// Failed - check if should retry
		if item.retryCount >= abm.maxRetries {
			logger.L().Error("Bulk send failed after max retries",
				helpers.String("containerID", item.containerID),
				helpers.Int("alertCount", len(item.alerts)),
				helpers.Int("retries", item.retryCount),
				helpers.Error(err))
			return
		}

		// Retry with exponential backoff
		item.retryCount++
		item.lastAttemptAt = time.Now()

		// Calculate delay: min(baseDelay * 2^(retryCount-1), maxDelay)
		delay := time.Duration(float64(abm.retryBaseDelay) * math.Pow(2, float64(item.retryCount-1)))
		if delay > abm.retryMaxDelay {
			delay = abm.retryMaxDelay
		}

		logger.L().Warning("Bulk send failed, will retry",
			helpers.String("containerID", item.containerID),
			helpers.Int("alertCount", len(item.alerts)),
			helpers.Int("retryCount", item.retryCount),
			helpers.String("retryAfter", delay.String()),
			helpers.Error(err))

		// Sleep with interruptible context
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			// Retry time reached, loop will retry
		case <-abm.stopChan:
			timer.Stop()
			// Shutdown requested, try one last time without delay
			logger.L().Info("Shutdown requested during retry delay, attempting final send",
				helpers.String("containerID", item.containerID))
			// Loop will retry immediately
		}
		// Continue loop to retry
	}
}

// drainSendQueue processes all remaining items in queue with a timeout
func (abm *AlertBulkManager) drainSendQueue() {
	// Flush all pending bulks from the bulk map first
	abm.Lock()
	bulksToFlush := make(map[string]*containerBulk)
	for containerID, bulk := range abm.bulks {
		bulksToFlush[containerID] = bulk
		delete(abm.bulks, containerID)
	}
	abm.Unlock()

	// Enqueue remaining bulks
	for containerID, bulk := range bulksToFlush {
		alerts, processTree, cloudServices := bulk.flush()
		if len(alerts) > 0 {
			item := &bulkQueueItem{
				containerID:   containerID,
				alerts:        alerts,
				processTree:   processTree,
				cloudServices: cloudServices,
				retryCount:    0,
				enqueuedAt:    time.Now(),
			}
			// Non-blocking send
			select {
			case abm.sendQueue <- item:
				// Enqueued successfully
			default:
				logger.L().Warning("Queue full during drain, dropping bulk",
					helpers.String("containerID", containerID),
					helpers.Int("alertCount", len(alerts)))
			}
		}
	}

	// Process all remaining items in queue with a timeout
	timeout := time.After(30 * time.Second)

	for {
		select {
		case item := <-abm.sendQueue:
			// Try to send without retries during drain
			err := abm.sendFunc(item.containerID, item.alerts, item.processTree, item.cloudServices)
			if err != nil {
				logger.L().Warning("Failed to send bulk during drain",
					helpers.String("containerID", item.containerID),
					helpers.Error(err))
			}
		case <-timeout:
			remaining := len(abm.sendQueue)
			if remaining > 0 {
				logger.L().Warning("Timeout draining send queue",
					helpers.Int("remainingItems", remaining))
			}
			return
		default:
			// Queue is empty
			return
		}
	}
}

// backgroundFlush runs periodically to flush timed-out bulks
func (abm *AlertBulkManager) backgroundFlush() {
	defer abm.wg.Done()

	ticker := time.NewTicker(abm.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			abm.checkAndFlushTimedOutBulks()
		case <-abm.stopChan:
			return
		}
	}
}

// checkAndFlushTimedOutBulks checks all bulks and flushes those that have timed out
func (abm *AlertBulkManager) checkAndFlushTimedOutBulks() {
	abm.Lock()
	// Collect bulks to flush and remove them from map atomically
	bulksToFlush := make(map[string]*containerBulk)
	for containerID, bulk := range abm.bulks {
		if bulk.shouldFlush() {
			bulksToFlush[containerID] = bulk
			delete(abm.bulks, containerID)
		}
	}
	abm.Unlock()

	// Flush outside the lock to avoid holding lock during enqueue
	for containerID, bulk := range bulksToFlush {
		abm.sendBulk(containerID, bulk)
	}
}

// GetBulkCount returns the number of active bulks (for monitoring/testing)
func (abm *AlertBulkManager) GetBulkCount() int {
	abm.RLock()
	defer abm.RUnlock()
	return len(abm.bulks)
}

// sendBulkWrapper is a helper to adapt the bulk send to HTTPExporter's sendAlert method
func (e *HTTPExporter) sendBulkWrapper(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.config.TimeoutSeconds)*time.Second)
	defer cancel()

	payload := e.createAlertPayload(alerts, processTree, cloudServices)
	return e.sendHTTPRequest(ctx, payload)
}
