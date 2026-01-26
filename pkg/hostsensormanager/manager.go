package hostsensormanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// manager implements the HostSensorManager interface
type manager struct {
	config    Config
	crdClient *CRDClient
	sensors   []Sensor
	stopCh    chan struct{}
	wg        sync.WaitGroup
	startOnce sync.Once
}

// NewHostSensorManager creates a new host sensor manager
func NewHostSensorManager(config Config) (HostSensorManager, error) {
	if !config.Enabled {
		return NewNoopHostSensorManager(), nil
	}

	if config.NodeName == "" {
		return nil, fmt.Errorf("node name is required")
	}

	if config.Interval == 0 {
		config.Interval = 5 * time.Minute // Default to 5 minutes
	}

	crdClient, err := NewCRDClient(config.NodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRD client: %w", err)
	}

	// Initialize sensors
	sensors := []Sensor{
		NewOsReleaseSensor(config.NodeName),
		NewKernelVersionSensor(config.NodeName),
		NewLinuxSecurityHardeningSensor(config.NodeName),
		NewOpenPortsSensor(config.NodeName),
		NewLinuxKernelVariablesSensor(config.NodeName),
		NewKubeletInfoSensor(config.NodeName),
		NewKubeProxyInfoSensor(config.NodeName),
		NewControlPlaneInfoSensor(config.NodeName),
		NewCloudProviderInfoSensor(config.NodeName),
		NewCNIInfoSensor(config.NodeName),
	}

	return &manager{
		config:    config,
		crdClient: crdClient,
		sensors:   sensors,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start begins the sensing loop
func (m *manager) Start(ctx context.Context) error {
	m.startOnce.Do(func() {
		logger.L().Info("starting host sensor manager",
			helpers.String("nodeName", m.config.NodeName),
			helpers.String("interval", m.config.Interval.String()))

		// Run initial sensing immediately
		m.runSensing(ctx)

		// Start periodic sensing
		m.wg.Add(1)
		go m.sensingLoop(ctx)
	})

	return nil
}

// Stop gracefully stops the manager
func (m *manager) Stop() error {
	logger.L().Info("stopping host sensor manager")
	select {
	case <-m.stopCh:
		// Already closed
		return nil
	default:
		close(m.stopCh)
	}
	m.wg.Wait()
	logger.L().Info("host sensor manager stopped")
	return nil
}

// sensingLoop runs the periodic sensing
func (m *manager) sensingLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L().Info("context cancelled, stopping sensing loop")
			return
		case <-m.stopCh:
			logger.L().Info("stop signal received, stopping sensing loop")
			return
		case <-ticker.C:
			m.runSensing(ctx)
		}
	}
}

// runSensing executes all sensors and updates CRDs
func (m *manager) runSensing(ctx context.Context) {
	logger.L().Debug("running host sensors", helpers.Int("sensorCount", len(m.sensors)))

	for _, sensor := range m.sensors {
		if err := m.runSensor(ctx, sensor); err != nil {
			logger.L().Warning("sensor failed",
				helpers.String("kind", sensor.GetKind()),
				helpers.Error(err))
		}
	}
}

// runSensor executes a single sensor and updates its CRD
func (m *manager) runSensor(ctx context.Context, sensor Sensor) error {
	logger.L().Debug("running sensor", helpers.String("kind", sensor.GetKind()))

	// Map Kind to Resource name (plural, lowercase)
	resource := sensor.GetPluralKind()

	// Sense the data
	data, err := sensor.Sense()
	if err != nil {
		// Update status with error
		if updateErr := m.crdClient.UpdateStatus(ctx, resource, err.Error()); updateErr != nil {
			logger.L().Warning("failed to update CRD status",
				helpers.String("kind", sensor.GetKind()),
				helpers.Error(updateErr))
		}
		return fmt.Errorf("failed to sense data: %w", err)
	}

	// Update CRD
	if err := m.crdClient.CreateOrUpdateHostData(ctx, resource, sensor.GetKind(), data); err != nil {
		return fmt.Errorf("failed to create/update CRD: %w", err)
	}

	logger.L().Debug("sensor completed successfully", helpers.String("kind", sensor.GetKind()))
	return nil
}

// noopManager is a no-op implementation when the manager is disabled
type noopManager struct{}

// NewNoopHostSensorManager creates a new no-op host sensor manager
func NewNoopHostSensorManager() HostSensorManager {
	return &noopManager{}
}

func (n *noopManager) Start(ctx context.Context) error {
	return nil
}

func (n *noopManager) Stop() error {
	return nil
}
