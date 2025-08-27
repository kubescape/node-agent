package hostfimsensor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// stripHostPath removes the host path prefix from a file path
func (h *HostFimSensorImpl) stripHostPath(fullPath string) string {
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
func (h *HostFimSensorImpl) getFileMetadata(filePath string) (size int64, inode uint64, device uint64, mtime, ctime time.Time, uid, gid uint32, mode uint32) {
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
func (h *HostFimSensorImpl) getProcessInfo() (pid uint32, name string, args []string) {
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
func (h *HostFimSensorImpl) getHostInfo() (hostname string) {
	if name, err := os.Hostname(); err == nil {
		hostname = name
	} else {
		hostname = "unknown"
	}
	return
}

// convertFsnotifyEventToFimEvent converts a fsnotify event to a FIM event
func (h *HostFimSensorImpl) convertFsnotifyEventToFimEvent(event fsnotify.Event) *fimtypes.FimEventImpl {
	fimEvent := &fimtypes.FimEventImpl{
		Timestamp: time.Now(),
	}

	// Strip the host path prefix to get the actual host path
	hostPath := h.stripHostPath(event.Name)
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

	// Process information is not available for fsnotify, so we set it to empty
	fimEvent.ProcessPid = 0
	fimEvent.ProcessName = ""
	fimEvent.ProcessArgs = []string{}

	// Get host information
	fimEvent.HostName = h.getHostInfo()
	fimEvent.AgentId = "kubescape-node-agent" // TODO: Make this configurable

	if event.Op&fsnotify.Create == fsnotify.Create {
		fimEvent.EventType = fimtypes.FimEventTypeCreate
	}

	if event.Op&fsnotify.Write == fsnotify.Write {
		fimEvent.EventType = fimtypes.FimEventTypeChange
	}

	if event.Op&fsnotify.Remove == fsnotify.Remove {
		fimEvent.EventType = fimtypes.FimEventTypeRemove
	}

	if event.Op&fsnotify.Rename == fsnotify.Rename {
		fimEvent.EventType = fimtypes.FimEventTypeRename
	}

	if event.Op&fsnotify.Chmod == fsnotify.Chmod {
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
