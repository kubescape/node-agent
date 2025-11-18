package exporters

import (
	"context"
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
	containerID       string
	alerts            []apitypes.RuntimeAlert
	mergedProcessTree apitypes.Process
	cloudServices     []string
	firstAlertTime    time.Time
	maxSize           int
	timeoutDuration   time.Duration
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

// addAlert adds an alert to the bulk and merges its process tree
func (cb *containerBulk) addAlert(alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) {
	cb.Lock()
	defer cb.Unlock()

	// Add alert (maintains temporal order since alerts are added sequentially)
	cb.alerts = append(cb.alerts, alert)

	// Set first alert time if this is the first alert
	if cb.firstAlertTime.IsZero() {
		cb.firstAlertTime = time.Now()
	}

	// Merge process tree (ProcessTree struct wraps Process in .ProcessTree field)
	if cb.mergedProcessTree.PID == 0 {
		// First alert - initialize with deep copy of this tree
		if processTree.ProcessTree.PID != 0 {
			cb.mergedProcessTree = *processTree.ProcessTree.DeepCopy()
		}
	} else {
		// Subsequent alerts - merge into existing tree
		if processTree.ProcessTree.PID != 0 {
			utils.MergeProcessTrees(&cb.mergedProcessTree, &processTree.ProcessTree)
		}
	}

	// Merge cloud services
	cb.cloudServices = utils.MergeCloudServices(cb.cloudServices, cloudServices)
}

// flush returns the bulk data and resets the bulk
func (cb *containerBulk) flush() ([]apitypes.RuntimeAlert, apitypes.ProcessTree, []string) {
	cb.Lock()
	defer cb.Unlock()

	alerts := cb.alerts
	// ProcessTree struct wraps Process in .ProcessTree field
	processTree := apitypes.ProcessTree{
		ProcessTree: cb.mergedProcessTree,
	}
	cloudServices := cb.cloudServices

	// Reset for potential reuse (though typically bulk is removed after flush)
	cb.alerts = nil
	cb.mergedProcessTree = apitypes.Process{}
	cb.cloudServices = nil
	cb.firstAlertTime = time.Time{}

	return alerts, processTree, cloudServices
}

// AlertBulkManager manages alert bulks per container
type AlertBulkManager struct {
	sync.RWMutex
	bulks               map[string]*containerBulk
	bulkMaxAlerts       int
	bulkTimeoutDuration time.Duration
	flushInterval       time.Duration
	sendFunc            func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error
	stopChan            chan struct{}
	wg                  sync.WaitGroup
}

// NewAlertBulkManager creates a new alert bulk manager
func NewAlertBulkManager(
	bulkMaxAlerts int,
	bulkTimeoutSeconds int,
	sendFunc func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error,
) *AlertBulkManager {
	return &AlertBulkManager{
		bulks:               make(map[string]*containerBulk),
		bulkMaxAlerts:       bulkMaxAlerts,
		bulkTimeoutDuration: time.Duration(bulkTimeoutSeconds) * time.Second,
		flushInterval:       1 * time.Second, // Fixed 1 second interval
		sendFunc:            sendFunc,
		stopChan:            make(chan struct{}),
	}
}

// Start begins the background flush goroutine
func (abm *AlertBulkManager) Start() {
	abm.wg.Add(1)
	go abm.backgroundFlush()
	logger.L().Info("Alert bulk manager started")
}

// Stop stops the background flush goroutine and flushes all pending bulks
func (abm *AlertBulkManager) Stop() {
	close(abm.stopChan)
	abm.wg.Wait()

	// Flush all remaining bulks
	abm.FlushAll()
	logger.L().Info("Alert bulk manager stopped")
}

// AddAlert adds an alert to the appropriate container bulk
func (abm *AlertBulkManager) AddAlert(alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) {
	containerID := alert.RuntimeAlertK8sDetails.ContainerID
	if containerID == "" {
		logger.L().Warning("AlertBulkManager.AddAlert - containerID is empty, cannot add to bulk")
		return
	}

	// Get or create bulk for this container
	abm.Lock()
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
	abm.Unlock()

	// Add alert to bulk
	bulk.addAlert(alert, processTree, cloudServices)

	// Check if bulk should be flushed immediately (size limit reached)
	if bulk.shouldFlush() {
		abm.flushBulk(containerID)
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
	// Remove bulk from map immediately
	delete(abm.bulks, containerID)
	abm.Unlock()

	// Flush the bulk data
	alerts, processTree, cloudServices := bulk.flush()

	if len(alerts) == 0 {
		return
	}

	logger.L().Debug("AlertBulkManager - flushing bulk",
		helpers.String("containerID", containerID),
		helpers.Int("alertCount", len(alerts)))

	// Send the bulk
	if err := abm.sendFunc(containerID, alerts, processTree, cloudServices); err != nil {
		logger.L().Warning("AlertBulkManager - failed to send bulk",
			helpers.String("containerID", containerID),
			helpers.Error(err))
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
	abm.RLock()
	containerIDs := make([]string, 0)
	for containerID, bulk := range abm.bulks {
		if bulk.shouldFlush() {
			containerIDs = append(containerIDs, containerID)
		}
	}
	abm.RUnlock()

	// Flush timed-out bulks
	for _, containerID := range containerIDs {
		abm.flushBulk(containerID)
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

