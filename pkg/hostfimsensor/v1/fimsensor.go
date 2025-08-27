package hostfimsensor

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
)

type HostFimSensor interface {
	Start() error
	Stop()
}

type HostFimPathConfig struct {
	Path     string
	OnCreate bool
	OnChange bool
	OnRemove bool
	OnRename bool
	OnChmod  bool
	OnMove   bool
}

type HostFimBatchConfig struct {
	MaxBatchSize int           // Maximum number of events in a batch
	BatchTimeout time.Duration // Maximum time to wait before sending a batch
}

type HostFimDedupConfig struct {
	DedupEnabled    bool          // Whether de-duplication is enabled
	DedupTimeWindow time.Duration // Time window for de-duplication (default: 1 minute)
	MaxCacheSize    int           // Maximum number of events to cache (default: 1000)
}

type HostFimSensorImpl struct {
	hostPath       string
	running        bool
	watcher        *fsnotify.Watcher
	pathConfigs    []HostFimPathConfig
	batchConfig    HostFimBatchConfig
	dedupConfig    HostFimDedupConfig
	exporter       exporters.Exporter
	batchCollector *batchCollector
	dedupCache     *dedupCache
}

func NewHostFimSensor(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter) HostFimSensor {
	// Try fanotify first for better subdirectory support
	fanotifySensor := NewHostFimSensorFanotify(hostPath, pathConfigs, exporter)

	// Test if fanotify works by trying to start it
	if err := fanotifySensor.Start(); err != nil {
		logger.L().Warning("Fanotify failed, falling back to fsnotify", helpers.Error(err))
		fanotifySensor.Stop()
		return NewHostFimSensorFsnotify(hostPath, pathConfigs, exporter)
	}

	fanotifySensor.Stop()
	return fanotifySensor
}

// NewHostFimSensorFsnotify creates a new fsnotify-based FIM sensor (fallback implementation)
func NewHostFimSensorFsnotify(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter) HostFimSensor {
	return NewHostFimSensorFsnotifyWithBatching(hostPath, pathConfigs, exporter, HostFimBatchConfig{
		MaxBatchSize: 1000,
		BatchTimeout: time.Minute,
	})
}

// NewHostFimSensorFsnotifyWithBatching creates a new fsnotify-based FIM sensor with batching
func NewHostFimSensorFsnotifyWithBatching(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig) HostFimSensor {
	return NewHostFimSensorFsnotifyWithConfig(hostPath, pathConfigs, exporter, batchConfig, HostFimDedupConfig{
		DedupEnabled:    true,
		DedupTimeWindow: 5 * time.Minute,
		MaxCacheSize:    1000,
	})
}

// NewHostFimSensorFsnotifyWithConfig creates a new fsnotify-based FIM sensor with full configuration
func NewHostFimSensorFsnotifyWithConfig(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig, dedupConfig HostFimDedupConfig) HostFimSensor {
	return &HostFimSensorImpl{
		hostPath:    hostPath,
		running:     false,
		pathConfigs: pathConfigs,
		batchConfig: batchConfig,
		dedupConfig: dedupConfig,
		exporter:    exporter,
	}
}

func NewHostFimSensorWithBatching(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig) HostFimSensor {
	// Try fanotify first for better subdirectory support
	fanotifySensor := NewHostFimSensorFanotifyWithBatching(hostPath, pathConfigs, exporter, batchConfig)

	// Test if fanotify works by trying to start it
	if err := fanotifySensor.Start(); err != nil {
		logger.L().Warning("Fanotify failed, falling back to fsnotify", helpers.Error(err))
		fanotifySensor.Stop()
		return NewHostFimSensorFsnotifyWithBatching(hostPath, pathConfigs, exporter, batchConfig)
	}

	fanotifySensor.Stop()
	return fanotifySensor
}

func NewHostFimSensorWithConfig(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig, dedupConfig HostFimDedupConfig) HostFimSensor {
	// Try fanotify first for better subdirectory support
	fanotifySensor := NewHostFimSensorFanotifyWithConfig(hostPath, pathConfigs, exporter, batchConfig, dedupConfig)

	// Test if fanotify works by trying to start it
	if err := fanotifySensor.Start(); err != nil {
		logger.L().Warning("Fanotify failed, falling back to fsnotify", helpers.Error(err))
		fanotifySensor.Stop()
		return NewHostFimSensorFsnotifyWithConfig(hostPath, pathConfigs, exporter, batchConfig, dedupConfig)
	}

	fanotifySensor.Stop()
	return fanotifySensor
}

func (h *HostFimSensorImpl) Start() error {
	if h.running {
		return fmt.Errorf("host FIM sensor is already running")
	}

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	// Store watcher.
	h.watcher = watcher

	// Initialize batch collector
	h.batchCollector = newBatchCollector(h.exporter, h.batchConfig.MaxBatchSize, h.batchConfig.BatchTimeout)
	h.batchCollector.start()

	// Initialize de-duplication cache if enabled
	if h.dedupConfig.DedupEnabled {
		h.dedupCache = newDedupCache(h.dedupConfig.DedupTimeWindow, h.dedupConfig.MaxCacheSize)
		h.dedupCache.start()
	}

	// Start watching.
	go h.watch()

	// Add paths to watch.
	for _, pathConfig := range h.pathConfigs {
		fullPath := filepath.Join(h.hostPath, pathConfig.Path)
		err := h.watcher.Add(fullPath)
		if err != nil {
			h.watcher.Close()
			return fmt.Errorf("failed to add path %s to watch: %w", fullPath, err)
		}
	}

	h.running = true

	return nil
}

// convertFsnotifyEventToFimEvent converts a fsnotify event to a FIM event
func (h *HostFimSensorImpl) convertFsnotifyEventToFimEvent(event fsnotify.Event) *fimtypes.FimEventImpl {
	fimEvent := &fimtypes.FimEventImpl{
		Timestamp: time.Now(),
	}

	if event.Op&fsnotify.Create == fsnotify.Create {
		fimEvent.Path = event.Name
		fimEvent.EventType = fimtypes.FimEventTypeCreate
	}

	if event.Op&fsnotify.Write == fsnotify.Write {
		fimEvent.Path = event.Name
		fimEvent.EventType = fimtypes.FimEventTypeChange
	}

	if event.Op&fsnotify.Remove == fsnotify.Remove {
		fimEvent.Path = event.Name
		fimEvent.EventType = fimtypes.FimEventTypeRemove
	}

	if event.Op&fsnotify.Rename == fsnotify.Rename {
		fimEvent.Path = event.Name
		fimEvent.EventType = fimtypes.FimEventTypeRename
	}

	if event.Op&fsnotify.Chmod == fsnotify.Chmod {
		fimEvent.Path = event.Name
		fimEvent.EventType = fimtypes.FimEventTypeChmod
	}

	return fimEvent
}

func (h *HostFimSensorImpl) watch() {
	for {
		select {
		case event, ok := <-h.watcher.Events:
			{
				if !ok {
					logger.L().Debug("FIM watcher channel closed, exiting")
					// Channel is closed, exit the loop
					return
				}

				// Convert fsnotify event to FIM event.
				fimEvent := h.convertFsnotifyEventToFimEvent(event)

				if fimEvent.EventType == "" {
					continue
				}

				// Check for duplicates before adding to batch
				if h.dedupCache.isDuplicate(fimEvent.GetPath(), fimEvent.GetEventType()) {
					logger.L().Debug("FIM event duplicate detected, skipping",
						helpers.String("path", fimEvent.GetPath()),
						helpers.String("operation", string(fimEvent.GetEventType())))
					continue
				}

				// Add event to batch collector.
				h.batchCollector.addEvent(fimEvent)
			}
		case err, ok := <-h.watcher.Errors:
			{
				if !ok {
					// Channel is closed, exit the loop
					logger.L().Debug("FIM watcher channel closed, exiting")
					return
				}
				logger.L().Error("FIM watcher error: %v", helpers.Error(err))
			}
		}
	}
}

func (h *HostFimSensorImpl) Stop() {
	h.running = false
	h.watcher.Close()
	h.batchCollector.stop()
	if h.dedupCache != nil {
		h.dedupCache.stop()
	}
}

func (h *HostFimSensorImpl) IsRunning() bool {
	return h.running == true
}
