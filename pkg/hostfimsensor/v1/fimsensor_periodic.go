package hostfimsensor

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/hostfimsensor/v1/filetree"
)

// HostFimSensorPeriodic implements HostFimSensor using periodic scanning
type HostFimSensorPeriodic struct {
	hostPath       string
	running        bool
	config         HostFimConfig
	exporter       exporters.Exporter
	batchCollector *batchCollector
	dedupCache     *dedupCache
	stopChan       chan struct{}
	stopOnce       sync.Once

	// Periodic scanning components - now per-directory
	directorySnapshots map[string]*filetree.SnapshotManager
	comparator         *filetree.TreeComparator
	scanTicker         *time.Ticker
	lastScanTime       time.Time
	scanMutex          sync.Mutex
}

// NewHostFimSensorPeriodic creates a new periodic scanning FIM sensor
func NewHostFimSensorPeriodic(hostPath string, config HostFimConfig, exporter exporters.Exporter) HostFimSensor {
	return &HostFimSensorPeriodic{
		hostPath: hostPath,
		config:   config,
		exporter: exporter,
		stopChan: make(chan struct{}),
	}
}

// Start starts the periodic scanning sensor
func (h *HostFimSensorPeriodic) Start() error {
	if h.running {
		return fmt.Errorf("periodic FIM sensor is already running")
	}

	// Validate configuration
	if err := h.config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Initialize batch collector
	h.batchCollector = newBatchCollector(h.exporter, h.config.BatchConfig.MaxBatchSize, h.config.BatchConfig.BatchTimeout)
	h.batchCollector.start()

	// Initialize de-duplication cache if enabled
	if h.config.DedupConfig.DedupEnabled {
		h.dedupCache = newDedupCache(h.config.DedupConfig.DedupTimeWindow, h.config.DedupConfig.MaxCacheSize)
		h.dedupCache.start()
	}

	// Initialize snapshot managers for each configured directory
	h.directorySnapshots = make(map[string]*filetree.SnapshotManager)

	for _, dirConfig := range h.config.PathConfigs {
		snapshotConfig := filetree.SnapshotConfig{
			MaxScanDepth:    h.config.PeriodicConfig.MaxScanDepth,
			IncludeHidden:   h.config.PeriodicConfig.IncludeHidden,
			ExcludePatterns: h.config.PeriodicConfig.ExcludePatterns,
			MaxFileSize:     h.config.PeriodicConfig.MaxFileSize,
			FollowSymlinks:  h.config.PeriodicConfig.FollowSymlinks,
		}

		h.directorySnapshots[dirConfig.Path] = filetree.NewSnapshotManager(
			h.config.PeriodicConfig.MaxSnapshotNodes,
			snapshotConfig,
		)
	}

	// Initialize tree comparator
	h.comparator = filetree.NewTreeComparator()

	// Create initial snapshots for each configured directory
	logger.L().Debug("Creating initial snapshots for periodic FIM sensor",
		helpers.String("host_path", h.hostPath),
		helpers.String("scan_interval", h.config.PeriodicConfig.ScanInterval.String()),
		helpers.Int("directory_count", len(h.config.PathConfigs)))

	if err := h.performInitialScan(); err != nil {
		h.cleanup()
		return fmt.Errorf("failed to create initial snapshots: %w", err)
	}

	// Start periodic scanning
	h.scanTicker = time.NewTicker(h.config.PeriodicConfig.ScanInterval)
	h.running = true

	go h.scanPeriodically()

	logger.L().Info("Periodic FIM sensor started successfully",
		helpers.String("scan_interval", h.config.PeriodicConfig.ScanInterval.String()),
		helpers.Int("monitored_directories", len(h.config.PathConfigs)))

	return nil
}

// Stop stops the periodic scanning sensor
func (h *HostFimSensorPeriodic) Stop() {
	h.stopOnce.Do(func() {
		h.running = false

		if h.scanTicker != nil {
			h.scanTicker.Stop()
		}

		close(h.stopChan)

		if h.batchCollector != nil {
			h.batchCollector.stop()
		}

		if h.dedupCache != nil {
			h.dedupCache.stop()
		}

		h.cleanup()

		logger.L().Info("Periodic FIM sensor stopped")
	})
}

// IsRunning returns whether the sensor is currently running
func (h *HostFimSensorPeriodic) IsRunning() bool {
	return h.running
}

// createSnapshotForDirectory creates a snapshot for a specific directory
func (h *HostFimSensorPeriodic) createSnapshotForDirectory(dirConfig HostFimPathConfig, isInitial bool) error {
	// Prepend hostPath to create full container path
	fullPath := filepath.Join(h.hostPath, dirConfig.Path)

	if isInitial {
		logger.L().Debug("Creating initial snapshot for directory",
			helpers.String("directory", dirConfig.Path),
			helpers.String("full_path", fullPath))
	}

	_, err := h.directorySnapshots[dirConfig.Path].CreateSnapshot(fullPath)
	if err != nil {
		return fmt.Errorf("snapshot creation failed for directory %s: %w", dirConfig.Path, err)
	}

	return nil
}

// performInitialScan creates the first snapshot for each configured directory without comparison
func (h *HostFimSensorPeriodic) performInitialScan() error {
	h.scanMutex.Lock()
	defer h.scanMutex.Unlock()

	logger.L().Debug("Performing initial scan for configured directories",
		helpers.String("host_path", h.hostPath))

	for _, dirConfig := range h.config.PathConfigs {
		if err := h.createSnapshotForDirectory(dirConfig, true); err != nil {
			return fmt.Errorf("initial snapshot creation failed for directory %s: %w", dirConfig.Path, err)
		}
	}

	h.lastScanTime = time.Now()
	return nil
}

// scanPeriodically runs the periodic scanning loop
func (h *HostFimSensorPeriodic) scanPeriodically() {
	for {
		select {
		case <-h.scanTicker.C:
			if err := h.performScan(); err != nil {
				logger.L().Error("Periodic scan failed, will retry next cycle",
					helpers.Error(err),
					helpers.String("next_scan", time.Now().Add(h.config.PeriodicConfig.ScanInterval).String()))

				// Clear current snapshots on error for all directories
				for _, snapshotManager := range h.directorySnapshots {
					snapshotManager.ClearCurrentSnapshot()
				}
			}
		case <-h.stopChan:
			return
		}
	}
}

// performScan performs a single scan and compares with previous snapshots for each directory
func (h *HostFimSensorPeriodic) performScan() error {
	h.scanMutex.Lock()
	defer h.scanMutex.Unlock()

	logger.L().Debug("Starting periodic scan for configured directories",
		helpers.String("host_path", h.hostPath),
		helpers.String("last_scan", h.lastScanTime.String()))

	var totalChanges int

	// Scan each configured directory individually
	for _, dirConfig := range h.config.PathConfigs {
		dirPath := dirConfig.Path
		snapshotManager := h.directorySnapshots[dirPath]

		logger.L().Debug("Scanning directory",
			helpers.String("directory", dirPath))

		// Attempt to create new snapshot for this directory
		if err := h.createSnapshotForDirectory(dirConfig, false); err != nil {
			logger.L().Error("Failed to create snapshot for directory",
				helpers.Error(err),
				helpers.String("directory", dirPath))

			// Clear current snapshot on error for this directory
			snapshotManager.ClearCurrentSnapshot()
			continue // Continue with other directories
		}

		// Get the new snapshot for comparison
		newSnapshot := snapshotManager.GetCurrentSnapshot()

		// Compare with previous snapshot if available
		if snapshotManager.HasPreviousSnapshot() {
			oldSnapshot := snapshotManager.GetPreviousSnapshot()

			// Detect changes for this directory
			changes := h.comparator.CompareSnapshots(oldSnapshot, newSnapshot)

			if len(changes) > 0 {
				logger.L().Debug("Detected file changes in directory",
					helpers.String("directory", dirPath),
					helpers.Int("change_count", len(changes)))

				totalChanges += len(changes)

				// Convert changes to FIM events
				events := h.comparator.ConvertToFimEvents(changes, h.hostPath)

				// Filter events based on path configuration
				filteredEvents := h.filterEventsByPathConfig(events, dirConfig)

				// Send events through existing pipeline
				for _, event := range filteredEvents {
					// Check for duplicates before adding to batch
					if h.dedupCache != nil && h.dedupCache.isDuplicate(event.GetPath(), event.GetEventType()) {
						logger.L().Debug("FIM event duplicate detected, skipping",
							helpers.String("path", event.GetPath()),
							helpers.String("operation", string(event.GetEventType())))
						continue
					}

					h.batchCollector.addEvent(event)
				}
			} else {
				logger.L().Debug("No changes detected in directory",
					helpers.String("directory", dirPath))
			}
		} else {
			logger.L().Debug("No previous snapshot available for comparison in directory",
				helpers.String("directory", dirPath))
		}
	}

	if totalChanges > 0 {
		logger.L().Info("Periodic scan completed with changes detected",
			helpers.Int("total_changes", totalChanges))
	}

	h.lastScanTime = time.Now()
	return nil
}

// filterEventsByPathConfig filters events based on the specific path configuration
func (h *HostFimSensorPeriodic) filterEventsByPathConfig(events []fimtypes.FimEvent, pathConfig HostFimPathConfig) []fimtypes.FimEvent {
	var filteredEvents []fimtypes.FimEvent

	for _, event := range events {
		// Check if this event type is enabled for this path
		if h.isEventTypeEnabled(event.GetEventType(), &pathConfig) {
			filteredEvents = append(filteredEvents, event)
		}
	}

	return filteredEvents
}

// isEventTypeEnabled checks if an event type is enabled for a path configuration
func (h *HostFimSensorPeriodic) isEventTypeEnabled(eventType fimtypes.FimEventType, pathCfg *HostFimPathConfig) bool {
	switch eventType {
	case fimtypes.FimEventTypeCreate:
		return pathCfg.OnCreate
	case fimtypes.FimEventTypeChange:
		return pathCfg.OnChange
	case fimtypes.FimEventTypeRemove:
		return pathCfg.OnRemove
	case fimtypes.FimEventTypeRename:
		return pathCfg.OnRename
	case fimtypes.FimEventTypeChmod:
		return pathCfg.OnChmod
	case fimtypes.FimEventTypeMove:
		return pathCfg.OnMove
	default:
		return false
	}
}

// cleanup performs cleanup operations
func (h *HostFimSensorPeriodic) cleanup() {
	for _, snapshotManager := range h.directorySnapshots {
		if snapshotManager != nil {
			snapshotManager.Cleanup()
		}
	}
}

// GetSnapshotStats returns current snapshot statistics for all monitored directories
func (h *HostFimSensorPeriodic) GetSnapshotStats() map[string]struct{ Current, Previous int } {
	stats := make(map[string]struct{ Current, Previous int })

	for dirPath, snapshotManager := range h.directorySnapshots {
		if snapshotManager != nil {
			current, previous := snapshotManager.GetSnapshotStats()
			stats[dirPath] = struct{ Current, Previous int }{Current: current, Previous: previous}
		}
	}

	return stats
}

// GetLastScanTime returns the time of the last successful scan
func (h *HostFimSensorPeriodic) GetLastScanTime() time.Time {
	h.scanMutex.Lock()
	defer h.scanMutex.Unlock()
	return h.lastScanTime
}
