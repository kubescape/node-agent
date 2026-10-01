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
	config      Config
	crdClient   *CRDClient
	sensors     []Sensor
	stopCh      chan struct{}
	wg          sync.WaitGroup
	startOnce   sync.Once
	lifecycleMu sync.Mutex
	stopped     bool
	cancel      context.CancelFunc
	collector   *garbageCollector
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

	var collector *garbageCollector
	if config.Namespace == "" {
		logger.L().Warning("host-data cleanup disabled: namespace is missing")
	} else {
		collector, err = newGarbageCollector(config, crdClient)
		if err != nil {
			logger.L().Warning("host-data cleanup disabled: cannot create election client", helpers.Error(err))
		}
	}

	return &manager{
		config:    config,
		collector: collector,
		crdClient: crdClient,
		sensors:   supportedHostSensors(config.NodeName),
		stopCh:    make(chan struct{}),
	}, nil
}

func supportedHostSensors(nodeName string) []Sensor {
	return []Sensor{
		NewOsReleaseSensor(nodeName),
		NewKernelVersionSensor(nodeName),
		NewLinuxSecurityHardeningSensor(nodeName),
		NewOpenPortsSensor(nodeName),
		NewLinuxKernelVariablesSensor(nodeName),
		NewKubeletInfoSensor(nodeName),
		NewKubeProxyInfoSensor(nodeName),
		NewControlPlaneInfoSensor(nodeName),
		NewCloudProviderInfoSensor(nodeName),
		NewCNIInfoSensor(nodeName),
	}
}

// Start begins the sensing loop
func (m *manager) Start(ctx context.Context) error {
	m.startOnce.Do(func() {
		m.lifecycleMu.Lock()
		if m.stopped {
			m.lifecycleMu.Unlock()
			return
		}
		ctx, m.cancel = context.WithCancel(ctx)
		logger.L().Info("starting host sensor manager",
			helpers.String("nodeName", m.config.NodeName),
			helpers.String("interval", m.config.Interval.String()))
		if m.collector != nil {
			m.wg.Add(1)
			go func() { defer m.wg.Done(); m.collector.run(ctx) }()
		}
		// Register sensing before unlocking so Stop can safely wait even during
		// initial sensing, without holding the mutex needed to cancel its requests.
		m.wg.Add(1)
		m.lifecycleMu.Unlock()
		m.runSensing(ctx)
		go m.sensingLoop(ctx)
	})
	return nil
}

// Stop cancels background operations and waits for them. A stopped manager is
// not restartable; concurrent and repeated calls are safe.
func (m *manager) Stop() error {
	m.lifecycleMu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
		if m.cancel != nil {
			m.cancel()
		}
	}
	m.lifecycleMu.Unlock()
	m.wg.Wait()
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
		if ctx.Err() != nil {
			return
		}
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
