package hostfimsensor

import (
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
)

// batchCollector handles batching of FIM events
type batchCollector struct {
	mu           sync.Mutex
	currentBatch []fimtypes.FimEvent
	exporter     exporters.Exporter
	maxBatchSize int
	batchTimeout time.Duration
	timer        *time.Timer
	stopChan     chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
}

// newBatchCollector creates a new batch collector
func newBatchCollector(exporter exporters.Exporter, maxBatchSize int, batchTimeout time.Duration) *batchCollector {
	return &batchCollector{
		currentBatch: make([]fimtypes.FimEvent, 0, maxBatchSize),
		exporter:     exporter,
		maxBatchSize: maxBatchSize,
		batchTimeout: batchTimeout,
		stopChan:     make(chan struct{}),
	}
}

// start begins the batch collector
func (bc *batchCollector) start() {
	bc.wg.Add(1)
	go bc.run()
}

// stop stops the batch collector and waits for it to finish
func (bc *batchCollector) stop() {
	bc.stopOnce.Do(func() {
		close(bc.stopChan)
	})
	bc.wg.Wait()
}

// run is the main loop for the batch collector
func (bc *batchCollector) run() {
	defer bc.wg.Done()

	bc.timer = time.NewTimer(bc.batchTimeout)
	defer bc.timer.Stop()

	for {
		select {
		case <-bc.timer.C:
			bc.sendBatch()
			bc.timer.Reset(bc.batchTimeout)
		case <-bc.stopChan:
			// Send any remaining events before stopping
			bc.sendBatch()
			return
		}
	}
}

// addEvent adds an event to the current batch and sends if full
func (bc *batchCollector) addEvent(event fimtypes.FimEvent) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	bc.currentBatch = append(bc.currentBatch, event)

	// If batch is full, send it immediately
	if len(bc.currentBatch) >= bc.maxBatchSize {
		bc.sendBatchLocked()
	}
}

// sendBatch sends the current batch to the exporter
func (bc *batchCollector) sendBatch() {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.sendBatchLocked()
}

// sendBatchLocked sends the current batch (assumes lock is held)
func (bc *batchCollector) sendBatchLocked() {
	if len(bc.currentBatch) == 0 {
		return
	}

	// Create a copy of the batch to send
	batch := make([]fimtypes.FimEvent, len(bc.currentBatch))
	copy(batch, bc.currentBatch)

	// Clear the current batch
	bc.currentBatch = bc.currentBatch[:0]

	// Send the batch in a goroutine to avoid blocking
	go func() {
		bc.exporter.SendFimAlerts(batch)
		logger.L().Debug("FIM batch sent", helpers.Int("events", len(batch)))
	}()
}
