package fimmanager

import (
	"context"
	"fmt"
	"os"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	hostfimsensor "github.com/kubescape/node-agent/pkg/hostfimsensor/v1"
)

// FIMManager manages the File Integrity Monitoring functionality
type FIMManager struct {
	cfg           config.Config
	sensor        hostfimsensor.HostFimSensor
	exporter      exporters.Exporter
	clusterName   string
	nodeName      string
	cloudMetadata *apitypes.CloudMetadata
	running       bool
}

// NewFIMManager creates a new FIM manager
func NewFIMManager(cfg config.Config, clusterName, nodeName string, cloudMetadata *apitypes.CloudMetadata) (*FIMManager, error) {
	if !cfg.EnableFIM {
		logger.L().Info("FIM is disabled in configuration")
		return &FIMManager{
			cfg:         cfg,
			clusterName: clusterName,
			nodeName:    nodeName,
			running:     false,
		}, nil
	}

	// Initialize FIM-specific exporters
	fimExportersConfig := cfg.FIM.GetFIMExportersConfig()
	exporter := exporters.InitExporters(fimExportersConfig, clusterName, nodeName, cloudMetadata)

	// Get path configurations
	pathConfigs := cfg.FIM.GetFIMPathConfigs()
	if len(pathConfigs) == 0 {
		return nil, fmt.Errorf("no directories configured for FIM monitoring")
	}

	// Get host root path from environment variable
	hostRoot, exists := os.LookupEnv("HOST_ROOT")
	if !exists {
		hostRoot = "/host"
	}

	// Create FIM sensor with backend selection based on configuration
	hostFimConfig := hostfimsensor.HostFimConfig{
		BackendConfig:  cfg.FIM.BackendConfig,
		PathConfigs:    pathConfigs,
		BatchConfig:    cfg.FIM.BatchConfig,
		DedupConfig:    cfg.FIM.DedupConfig,
		PeriodicConfig: cfg.FIM.PeriodicConfig,
	}

	sensor, err := hostfimsensor.NewHostFimSensorWithBackend(
		hostRoot, // host root path mount
		hostFimConfig,
		exporter,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create FIM sensor: %w", err)
	}

	return &FIMManager{
		cfg:           cfg,
		sensor:        sensor,
		exporter:      exporter,
		clusterName:   clusterName,
		nodeName:      nodeName,
		cloudMetadata: cloudMetadata,
		running:       false,
	}, nil
}

// Start starts the FIM monitoring
func (fm *FIMManager) Start(ctx context.Context) error {
	if !fm.cfg.EnableFIM {
		logger.L().Info("FIM is disabled, skipping start")
		return nil
	}

	if fm.running {
		return fmt.Errorf("FIM manager is already running")
	}

	logger.L().Info("Starting FIM monitoring",
		helpers.String("clusterName", fm.clusterName),
		helpers.String("nodeName", fm.nodeName),
		helpers.Int("directories", len(fm.cfg.FIM.Directories)))

	// Start the FIM sensor
	err := fm.sensor.Start()
	if err != nil {
		return fmt.Errorf("failed to start FIM sensor: %w", err)
	}

	fm.running = true
	logger.L().Info("FIM monitoring started successfully")
	return nil
}

// Stop stops the FIM monitoring
func (fm *FIMManager) Stop() {
	if !fm.running {
		return
	}

	logger.L().Info("Stopping FIM monitoring")
	fm.sensor.Stop()
	fm.running = false
	logger.L().Info("FIM monitoring stopped")
}

// IsRunning returns whether the FIM manager is running
func (fm *FIMManager) IsRunning() bool {
	return fm.running
}

// GetStatus returns the current status of the FIM manager
func (fm *FIMManager) GetStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":     fm.cfg.EnableFIM,
		"running":     fm.running,
		"directories": len(fm.cfg.FIM.Directories),
	}

	if fm.cfg.EnableFIM {
		status["backendConfig"] = fm.cfg.FIM.BackendConfig
		status["batchConfig"] = fm.cfg.FIM.BatchConfig
		status["dedupConfig"] = fm.cfg.FIM.DedupConfig
		if fm.cfg.FIM.PeriodicConfig != nil {
			status["periodicConfig"] = fm.cfg.FIM.PeriodicConfig
		}
	}

	return status
}
