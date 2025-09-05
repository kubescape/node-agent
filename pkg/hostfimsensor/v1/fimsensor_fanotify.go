//go:build linux
// +build linux

package hostfimsensor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/exporters"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/opcoder0/fanotify"
)

// HostFimSensorFanotify implements HostFimSensor using fanotify for subdirectory monitoring
type HostFimSensorFanotify struct {
	hostPath       string
	running        bool
	listeners      []*fanotify.Listener
	pathConfigs    []HostFimPathConfig
	batchConfig    HostFimBatchConfig
	dedupConfig    HostFimDedupConfig
	exporter       exporters.Exporter
	batchCollector *batchCollector
	dedupCache     *dedupCache
	stopChan       chan struct{}
	stopOnce       sync.Once
}

// NewHostFimSensorFanotify creates a new fanotify-based FIM sensor
func NewHostFimSensorFanotify(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter) HostFimSensor {
	return NewHostFimSensorFanotifyWithBatching(hostPath, pathConfigs, exporter, HostFimBatchConfig{
		MaxBatchSize: 1000,
		BatchTimeout: time.Minute,
	})
}

// NewHostFimSensorFanotifyWithBatching creates a new fanotify-based FIM sensor with batching
func NewHostFimSensorFanotifyWithBatching(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig) HostFimSensor {
	return NewHostFimSensorFanotifyWithConfig(hostPath, pathConfigs, exporter, batchConfig, HostFimDedupConfig{
		DedupEnabled:    true,
		DedupTimeWindow: 5 * time.Minute,
		MaxCacheSize:    1000,
	})
}

// NewHostFimSensorFanotifyWithConfig creates a new fanotify-based FIM sensor with full configuration
func NewHostFimSensorFanotifyWithConfig(hostPath string, pathConfigs []HostFimPathConfig, exporter exporters.Exporter, batchConfig HostFimBatchConfig, dedupConfig HostFimDedupConfig) HostFimSensor {
	return &HostFimSensorFanotify{
		hostPath:    hostPath,
		running:     false,
		listeners:   make([]*fanotify.Listener, 0),
		pathConfigs: pathConfigs,
		batchConfig: batchConfig,
		dedupConfig: dedupConfig,
		exporter:    exporter,
		stopChan:    make(chan struct{}),
	}
}

func (h *HostFimSensorFanotify) Start() error {
	if h.running {
		return fmt.Errorf("host FIM sensor is already running")
	}

	// Initialize batch collector
	h.batchCollector = newBatchCollector(h.exporter, h.batchConfig.MaxBatchSize, h.batchConfig.BatchTimeout)
	h.batchCollector.start()

	// Initialize de-duplication cache if enabled
	if h.dedupConfig.DedupEnabled {
		h.dedupCache = newDedupCache(h.dedupConfig.DedupTimeWindow, h.dedupConfig.MaxCacheSize)
		h.dedupCache.start()
	}

	// Create listeners for each path configuration
	for _, pathConfig := range h.pathConfigs {
		fullPath := filepath.Join(h.hostPath, pathConfig.Path)

		// Check if path exists
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			logger.L().Warning("FIM path does not exist, skipping", helpers.String("path", fullPath))
			continue
		}

		// Create a new listener for this path
		listener, err := fanotify.NewListener(fullPath, true, fanotify.PermissionNone)
		if err != nil {
			// Clean up any existing listeners
			h.cleanupListeners()
			return fmt.Errorf("failed to create fanotify listener for path %s: %w", fullPath, err)
		}

		// Add watch for the specific event types
		eventTypes := h.getFanotifyEventTypes(pathConfig)
		err = listener.AddWatch(fullPath, eventTypes)
		if err != nil {
			listener.Stop()
			h.cleanupListeners()
			return fmt.Errorf("failed to add watch for path %s: %w", fullPath, err)
		}

		// Start the listener
		listener.Start()

		h.listeners = append(h.listeners, listener)
		logger.L().Debug("FIM path marked for monitoring", helpers.String("path", fullPath))
	}

	// Start watching
	go h.watch()

	h.running = true
	return nil
}

// getFanotifyEventTypes converts HostFimPathConfig to fanotify event types
func (h *HostFimSensorFanotify) getFanotifyEventTypes(config HostFimPathConfig) fanotify.EventType {
	var eventTypes fanotify.EventType

	if config.OnCreate {
		eventTypes = eventTypes.Or(fanotify.FileCreated)
	}
	if config.OnChange {
		eventTypes = eventTypes.Or(fanotify.FileModified)
	}
	if config.OnRemove {
		eventTypes = eventTypes.Or(fanotify.FileDeleted)
	}
	if config.OnRename {
		eventTypes = eventTypes.Or(fanotify.FileMovedFrom)
		eventTypes = eventTypes.Or(fanotify.FileMovedTo)
	}
	if config.OnChmod {
		eventTypes = eventTypes.Or(fanotify.FileAttribChanged)
	}
	if config.OnMove {
		eventTypes = eventTypes.Or(fanotify.FileMovedFrom)
		eventTypes = eventTypes.Or(fanotify.FileMovedTo)
	}

	// Always include file access for tracking
	eventTypes = eventTypes.Or(fanotify.FileAccessed)

	return eventTypes
}

// stripHostPath removes the host path prefix from a file path
func (h *HostFimSensorFanotify) stripHostPath(fullPath string) string {
	// Remove the host path prefix to get the actual host path
	if strings.HasPrefix(fullPath, h.hostPath) {
		relativePath := strings.TrimPrefix(fullPath, h.hostPath)
		// Ensure the path starts with "/" for absolute paths
		if !strings.HasPrefix(relativePath, "/") {
			relativePath = "/" + relativePath
		}
		return relativePath
	}
	return fullPath
}

// getFileMetadata retrieves detailed file metadata
func (h *HostFimSensorFanotify) getFileMetadata(filePath string) (size int64, inode uint64, device uint64, mtime, ctime time.Time, uid, gid uint32, mode uint32) {
	// Get the full path including host prefix
	fullPath := filepath.Join(h.hostPath, filePath)

	// Get file info
	if info, err := os.Stat(fullPath); err == nil {
		size = info.Size()
		mtime = info.ModTime()

		// Get detailed stat info for inode, device, etc.
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			inode = stat.Ino
			device = uint64(stat.Dev)
			uid = stat.Uid
			gid = stat.Gid
			mode = uint32(stat.Mode)
			ctime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		}
	}

	return
}

// getProcessInfo retrieves information about the current process
func (h *HostFimSensorFanotify) getProcessInfo() (pid uint32, name string, args []string) {
	pid = uint32(os.Getpid())

	// Get process name from /proc/self/comm
	if comm, err := os.ReadFile("/proc/self/comm"); err == nil {
		name = strings.TrimSpace(string(comm))
	} else {
		name = "unknown"
	}

	// Get process args from /proc/self/cmdline
	if cmdline, err := os.ReadFile("/proc/self/cmdline"); err == nil {
		args = strings.Split(strings.Trim(string(cmdline), "\x00"), "\x00")
	} else {
		args = []string{name}
	}

	return
}

// getHostInfo retrieves basic host information
func (h *HostFimSensorFanotify) getHostInfo() (hostname string) {
	if name, err := os.Hostname(); err == nil {
		hostname = name
	} else {
		hostname = "unknown"
	}
	return
}

// convertFanotifyEventToFimEvent converts a fanotify event to a FIM event
func (h *HostFimSensorFanotify) convertFanotifyEventToFimEvent(event fanotify.Event) *fimtypes.FimEventImpl {
	fimEvent := &fimtypes.FimEventImpl{
		Timestamp: time.Now(),
	}

	// Build the full path
	var fullPath string
	if event.FileName != "" {
		fullPath = filepath.Join(event.Path, event.FileName)
	} else {
		fullPath = event.Path
	}

	// Strip the host path prefix to get the actual host path
	hostPath := h.stripHostPath(fullPath)
	fimEvent.Path = hostPath

	// Get enhanced file metadata
	fileSize, fileInode, fileDevice, fileMtime, fileCtime, uid, gid, mode := h.getFileMetadata(hostPath)
	fimEvent.FileSize = fileSize
	fimEvent.FileInode = fileInode
	fimEvent.FileDevice = fileDevice
	fimEvent.FileMtime = fileMtime
	fimEvent.FileCtime = fileCtime
	fimEvent.Uid = uid
	fimEvent.Gid = gid
	fimEvent.Mode = mode

	// Get process information
	processPid, processName, processArgs := h.getProcessInfo()
	fimEvent.ProcessPid = processPid
	fimEvent.ProcessName = processName
	fimEvent.ProcessArgs = processArgs

	// Get host information
	fimEvent.HostName = h.getHostInfo()
	fimEvent.AgentId = "kubescape-node-agent" // TODO: Make this configurable

	// Convert fanotify event types to FIM event type
	switch {
	case event.EventTypes.Has(fanotify.FileCreated):
		fimEvent.EventType = fimtypes.FimEventTypeCreate
	case event.EventTypes.Has(fanotify.FileModified):
		fimEvent.EventType = fimtypes.FimEventTypeChange
	case event.EventTypes.Has(fanotify.FileDeleted):
		fimEvent.EventType = fimtypes.FimEventTypeRemove
	case event.EventTypes.Has(fanotify.FileMovedFrom), event.EventTypes.Has(fanotify.FileMovedTo):
		fimEvent.EventType = fimtypes.FimEventTypeMove
	case event.EventTypes.Has(fanotify.FileAttribChanged):
		fimEvent.EventType = fimtypes.FimEventTypeChmod
	case event.EventTypes.Has(fanotify.FileAccessed):
		// For access events, we might want to track as a change or create depending on context
		// For now, we'll skip access events as they're too noisy
		return nil
	default:
		// Unknown event type, skip
		return nil
	}

	return fimEvent
}

func (h *HostFimSensorFanotify) watch() {
	// Create a channel to receive events from all listeners
	eventChan := make(chan fanotify.Event, 1000)

	// Start goroutines to read from each listener
	for _, listener := range h.listeners {
		go func(l *fanotify.Listener) {
			for {
				select {
				case <-h.stopChan:
					return
				case event := <-l.Events:
					select {
					case eventChan <- event:
					case <-h.stopChan:
						return
					}
				}
			}
		}(listener)
	}

	// Process events from all listeners
	for {
		select {
		case <-h.stopChan:
			logger.L().Debug("FIM fanotify watcher stopping")
			return
		case event := <-eventChan:
			// Convert fanotify event to FIM event
			fimEvent := h.convertFanotifyEventToFimEvent(event)
			if fimEvent == nil {
				continue
			}

			// Check for duplicates before adding to batch
			if h.dedupCache.isDuplicate(fimEvent.GetPath(), fimEvent.GetEventType()) {
				logger.L().Debug("FIM event duplicate detected, skipping",
					helpers.String("path", fimEvent.GetPath()),
					helpers.String("operation", string(fimEvent.GetEventType())))
				continue
			}

			// Add event to batch collector
			h.batchCollector.addEvent(fimEvent)
		}
	}
}

func (h *HostFimSensorFanotify) cleanupListeners() {
	for _, listener := range h.listeners {
		listener.Stop()
	}
	h.listeners = h.listeners[:0]
}

func (h *HostFimSensorFanotify) Stop() {
	if !h.running {
		return
	}

	h.running = false

	// Use sync.Once to ensure the channel is only closed once
	h.stopOnce.Do(func() {
		close(h.stopChan)
	})

	h.cleanupListeners()

	if h.batchCollector != nil {
		h.batchCollector.stop()
	}

	if h.dedupCache != nil {
		h.dedupCache.stop()
	}
}

func (h *HostFimSensorFanotify) IsRunning() bool {
	return h.running
}
