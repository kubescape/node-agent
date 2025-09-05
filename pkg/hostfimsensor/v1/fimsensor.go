package hostfimsensor

import (
	"fmt"
	"time"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/opcoder0/fanotify"
)

// FimBackendType represents the type of FIM backend to use
type FimBackendType string

const (
	FimBackendFanotify FimBackendType = "fanotify"
	FimBackendPeriodic FimBackendType = "periodic"
)

// HostFimBackendConfig holds backend selection configuration
type HostFimBackendConfig struct {
	BackendType FimBackendType // Explicit backend selection
}

// HostFimPeriodicConfig holds configuration for periodic scanning
type HostFimPeriodicConfig struct {
	ScanInterval     time.Duration // How often to scan (e.g., 5 minutes)
	MaxScanDepth     int           // Maximum directory depth to scan
	MaxSnapshotNodes int           // Maximum number of nodes in snapshot
	IncludeHidden    bool          // Whether to include hidden files
	ExcludePatterns  []string      // Glob patterns to exclude
	MaxFileSize      int64         // Maximum file size to track
	FollowSymlinks   bool          // Whether to follow symbolic links
}

// HostFimConfig holds the complete FIM configuration
type HostFimConfig struct {
	BackendConfig  HostFimBackendConfig
	PathConfigs    []HostFimPathConfig
	BatchConfig    HostFimBatchConfig
	DedupConfig    HostFimDedupConfig
	PeriodicConfig *HostFimPeriodicConfig // Only used for periodic backend
}

// DefaultHostFimConfig returns a default configuration
func DefaultHostFimConfig() HostFimConfig {
	return HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendFanotify, // Default to fanotify
		},
		PathConfigs: []HostFimPathConfig{
			{
				Path:     "/etc",
				OnCreate: true,
				OnChange: true,
				OnRemove: true,
				OnRename: true,
				OnChmod:  true,
				OnMove:   true,
			},
		},
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 1000,
			BatchTimeout: time.Minute,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: 5 * time.Minute,
			MaxCacheSize:    1000,
		},
		PeriodicConfig: nil, // Not set by default
	}
}

// DefaultPeriodicConfig returns default periodic scanning configuration
func DefaultPeriodicConfig() HostFimPeriodicConfig {
	return HostFimPeriodicConfig{
		ScanInterval:     5 * time.Minute,
		MaxScanDepth:     10,
		MaxSnapshotNodes: 100000, // 100K file limit
		IncludeHidden:    false,
		ExcludePatterns:  []string{"*.tmp", "*.log.*", "*.swp", "*.bak"},
		MaxFileSize:      100 * 1024 * 1024, // 100MB
		FollowSymlinks:   false,
	}
}

// Validate validates the configuration
func (c *HostFimConfig) Validate() error {
	// Validate backend type
	switch c.BackendConfig.BackendType {
	case FimBackendFanotify, FimBackendPeriodic:
		// Valid backend types
	default:
		return fmt.Errorf("invalid backend type: %s", c.BackendConfig.BackendType)
	}

	// Validate periodic config if using periodic backend
	if c.BackendConfig.BackendType == FimBackendPeriodic {
		if c.PeriodicConfig == nil {
			return fmt.Errorf("periodic backend requires PeriodicConfig")
		}
		if err := c.PeriodicConfig.Validate(); err != nil {
			return fmt.Errorf("invalid periodic config: %w", err)
		}
	}

	// Validate path configs
	if len(c.PathConfigs) == 0 {
		return fmt.Errorf("at least one path configuration is required")
	}

	// Validate batch config
	if c.BatchConfig.MaxBatchSize <= 0 {
		return fmt.Errorf("MaxBatchSize must be positive")
	}
	if c.BatchConfig.BatchTimeout <= 0 {
		return fmt.Errorf("BatchTimeout must be positive")
	}

	// Validate dedup config
	if c.DedupConfig.DedupEnabled {
		if c.DedupConfig.DedupTimeWindow <= 0 {
			return fmt.Errorf("DedupTimeWindow must be positive when deduplication is enabled")
		}
		if c.DedupConfig.MaxCacheSize <= 0 {
			return fmt.Errorf("MaxCacheSize must be positive when deduplication is enabled")
		}
	}

	return nil
}

// Validate validates the periodic configuration
func (c *HostFimPeriodicConfig) Validate() error {
	if c.ScanInterval <= 0 {
		return fmt.Errorf("ScanInterval must be positive")
	}
	if c.MaxScanDepth < 0 {
		return fmt.Errorf("MaxScanDepth must be non-negative")
	}
	if c.MaxSnapshotNodes <= 0 {
		return fmt.Errorf("MaxSnapshotNodes must be positive")
	}
	if c.MaxFileSize < 0 {
		return fmt.Errorf("MaxFileSize must be non-negative")
	}
	return nil
}

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

// NewHostFimSensorWithBackend creates a FIM sensor with explicit backend selection
func NewHostFimSensorWithBackend(
	hostPath string,
	config HostFimConfig,
	exporter exporters.Exporter,
) (HostFimSensor, error) {
	switch config.BackendConfig.BackendType {
	case FimBackendFanotify:
		if !canUseFanotify() {
			return nil, fmt.Errorf("fanotify backend requested but not available")
		}
		return NewHostFimSensorFanotifyWithConfig(hostPath, config.PathConfigs, exporter, config.BatchConfig, config.DedupConfig), nil

	case FimBackendPeriodic:
		if config.PeriodicConfig == nil {
			return nil, fmt.Errorf("periodic backend requires PeriodicConfig")
		}
		return NewHostFimSensorPeriodic(hostPath, config, exporter), nil

	default:
		return nil, fmt.Errorf("unknown backend type: %s", config.BackendConfig.BackendType)
	}
}

// canUseFanotify checks if fanotify is available without actually starting a sensor
func canUseFanotify() bool {
	// Try to create a temporary fanotify listener to test capability
	// Use a temporary directory that we know exists
	tempDir := "/tmp"

	// Try to create a fanotify listener
	listener, err := fanotify.NewListener(tempDir, true, fanotify.PermissionNone)
	if err != nil {
		return false
	}

	// If we can create it, we can use fanotify
	listener.Stop()
	return true
}
