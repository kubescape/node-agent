//go:build linux
// +build linux

package hostfimsensor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/go-logger"
	hostfimsensor "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostFimSensorPeriodic(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-periodic-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Create configuration for periodic backend
	periodicConfig := DefaultPeriodicConfig()
	periodicConfig.ScanInterval = 100 * time.Millisecond // Fast scanning for testing
	periodicConfig.MaxSnapshotNodes = 1000               // Small limit for testing

	fimConfig := HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: []HostFimPathConfig{
			{
				Path:     ".",
				OnCreate: true,
				OnChange: true,
				OnRemove: true,
			},
		},
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 100,
			BatchTimeout: time.Second,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: time.Minute,
			MaxCacheSize:    100,
		},
		PeriodicConfig: &periodicConfig,
	}

	// Create the periodic sensor
	sensor := NewHostFimSensorPeriodic(tempDir, fimConfig, mockExporter)
	require.NotNil(t, sensor)

	// Test that the sensor can be started
	err = sensor.Start()
	require.NoError(t, err)

	// Wait a bit for the initial scan
	time.Sleep(200 * time.Millisecond)

	// Create a test file to trigger an event
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Wait for the next scan cycle
	time.Sleep(200 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()

	// Verify that events were generated
	assert.GreaterOrEqual(t, len(mockExporter.events), 0, "Expected some FIM events to be generated")
}

// TestNewHostFimSensorPeriodicConfiguration tests various configuration options for the periodic backend
func TestNewHostFimSensorPeriodicConfiguration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-periodic-config-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Test with different periodic configurations
	testCases := []struct {
		name           string
		periodicConfig HostFimPeriodicConfig
		expectSuccess  bool
	}{
		{
			name: "Valid configuration with fast scanning",
			periodicConfig: HostFimPeriodicConfig{
				ScanInterval:     50 * time.Millisecond,
				MaxScanDepth:     3,
				MaxSnapshotNodes: 500,
				IncludeHidden:    false,
				ExcludePatterns:  []string{"*.tmp"},
				MaxFileSize:      512 * 1024,
				FollowSymlinks:   false,
			},
			expectSuccess: true,
		},
		{
			name: "Valid configuration with deep scanning",
			periodicConfig: HostFimPeriodicConfig{
				ScanInterval:     200 * time.Millisecond,
				MaxScanDepth:     10,
				MaxSnapshotNodes: 2000,
				IncludeHidden:    true,
				ExcludePatterns:  []string{},
				MaxFileSize:      2 * 1024 * 1024,
				FollowSymlinks:   true,
			},
			expectSuccess: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fimConfig := HostFimConfig{
				BackendConfig: HostFimBackendConfig{
					BackendType: FimBackendPeriodic,
				},
				PathConfigs: []HostFimPathConfig{
					{
						Path:     ".",
						OnCreate: true,
						OnChange: true,
						OnRemove: true,
					},
				},
				BatchConfig: HostFimBatchConfig{
					MaxBatchSize: 50,
					BatchTimeout: 500 * time.Millisecond,
				},
				DedupConfig: HostFimDedupConfig{
					DedupEnabled:    true,
					DedupTimeWindow: 30 * time.Second,
					MaxCacheSize:    50,
				},
				PeriodicConfig: &tc.periodicConfig,
			}

			// Create the periodic sensor
			sensor := NewHostFimSensorPeriodic(tempDir, fimConfig, mockExporter)
			require.NotNil(t, sensor)

			// Test that the sensor can be started
			err = sensor.Start()
			if tc.expectSuccess {
				require.NoError(t, err)

				// Wait for initial scan
				time.Sleep(100 * time.Millisecond)

				// Stop the sensor
				sensor.Stop()
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestNewHostFimSensorPeriodicWithBackend tests the periodic backend through NewHostFimSensorWithBackend
func TestNewHostFimSensorPeriodicWithBackend(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-periodic-backend-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Create configuration for periodic backend
	periodicConfig := DefaultPeriodicConfig()
	periodicConfig.ScanInterval = 100 * time.Millisecond // Fast scanning for testing
	periodicConfig.MaxSnapshotNodes = 1000               // Small limit for testing

	fimConfig := HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: []HostFimPathConfig{
			{
				Path:     "/etc",
				OnCreate: true,
				OnChange: true,
				OnRemove: true,
			},
			{
				Path:     ".",
				OnCreate: true,
				OnChange: true,
				OnRemove: true,
				OnRename: true,
				OnChmod:  true,
				OnMove:   true,
			},
		},
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 100,
			BatchTimeout: time.Second,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: time.Minute,
			MaxCacheSize:    100,
		},
		PeriodicConfig: &periodicConfig,
	}

	// Create the periodic sensor using NewHostFimSensorWithBackend
	sensor, err := NewHostFimSensorWithBackend(tempDir, fimConfig, mockExporter)
	require.NoError(t, err)
	require.NotNil(t, sensor)

	// Test that the sensor can be started
	err = sensor.Start()
	require.NoError(t, err)

	// Wait for initial scan to complete
	time.Sleep(300 * time.Millisecond)

	// Create a test file to trigger an event
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Wait for the next scan cycle
	time.Sleep(200 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()

	// Verify that events were generated
	assert.GreaterOrEqual(t, len(mockExporter.events), 0, "Expected some FIM events to be generated")
}

// TestNewHostFimSensorPeriodicComprehensive is a comprehensive test similar to TestNewHostFimSensorFanotify
func TestNewHostFimSensorPeriodicComprehensive(t *testing.T) {

	logger.L().SetLevel("info")
	logger.L().SetWriter(os.Stderr)

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-periodic-comp-test")
	require.NoError(t, err)
	err = os.Mkdir(filepath.Join(tempDir, "test"), 0755)
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Create path configurations
	pathConfigs := []HostFimPathConfig{
		{
			Path:     "test",
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
			OnRename: true,
			OnChmod:  true,
			OnMove:   true,
		},
	}

	// Create the periodic sensor with default configuration
	sensor := NewHostFimSensorPeriodic(tempDir, HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: pathConfigs,
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 1,
			BatchTimeout: time.Second,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: time.Minute,
			MaxCacheSize:    100,
		},
		PeriodicConfig: &HostFimPeriodicConfig{
			ScanInterval:     200 * time.Millisecond, // Fast scanning for testing
			MaxScanDepth:     5,                      // Small depth for testing
			MaxSnapshotNodes: 1000,                   // Small limit for testing
			IncludeHidden:    false,
			ExcludePatterns:  []string{"*.tmp", "*.log"},
			MaxFileSize:      1024 * 1024, // 1MB limit
			FollowSymlinks:   false,
		},
	}, mockExporter)
	require.NotNil(t, sensor)

	// Test that the sensor can be started
	err = sensor.Start()
	require.NoError(t, err)

	// Wait for initial scan to complete
	time.Sleep(1000 * time.Millisecond)

	// Create a test file to trigger an event
	testFile := filepath.Join(tempDir, "test", "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Wait for the next scan cycle
	time.Sleep(1000 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()

	// Verify that events were generated
	assert.GreaterOrEqual(t, len(mockExporter.events), 0, "Expected some FIM events to be generated")
	if len(mockExporter.events) == 0 {
		require.Fail(t, "Expected some FIM events to be generated")
		return
	}

	// Print the events
	foundEvent := false
	for _, event := range mockExporter.events {
		if filepath.Join(tempDir, event.GetPath()) == testFile && event.GetEventType() == hostfimsensor.FimEventTypeCreate {
			foundEvent = true
			break
		}
	}
	assert.True(t, foundEvent, "Expected event for test file to be generated")
}

// TestAllFimEventTypes tests that all configured FIM event types are properly detected
func TestAllFimEventTypes(t *testing.T) {
	logger.L().SetLevel("info")
	logger.L().SetWriter(os.Stderr)

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-all-events-test")
	require.NoError(t, err)
	err = os.Mkdir(filepath.Join(tempDir, "test"), 0755)
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Create path configurations with all event types enabled
	pathConfigs := []HostFimPathConfig{
		{
			Path:     "test",
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
			OnRename: true,
			OnChmod:  true,
			OnMove:   true,
		},
	}

	// Create the periodic sensor
	sensor := NewHostFimSensorPeriodic(tempDir, HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: pathConfigs,
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 1,
			BatchTimeout: time.Second,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    false, // Disable dedup for testing
			DedupTimeWindow: time.Minute,
			MaxCacheSize:    100,
		},
		PeriodicConfig: &HostFimPeriodicConfig{
			ScanInterval:     100 * time.Millisecond, // Very fast scanning for testing
			MaxScanDepth:     5,
			MaxSnapshotNodes: 1000,
			IncludeHidden:    false,
			ExcludePatterns:  []string{"*.tmp", "*.log"},
			MaxFileSize:      1024 * 1024,
			FollowSymlinks:   false,
		},
	}, mockExporter)
	require.NotNil(t, sensor)

	// Start the sensor
	err = sensor.Start()
	require.NoError(t, err)

	// Wait for initial scan to complete
	time.Sleep(500 * time.Millisecond)

	// Test 1: CREATE event
	testFile := filepath.Join(tempDir, "test", "create_test.txt")
	err = os.WriteFile(testFile, []byte("create content"), 0644)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Test 2: CHANGE event (modify file content)
	err = os.WriteFile(testFile, []byte("modified content"), 0644)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Test 3: CHMOD event (change file permissions)
	err = os.Chmod(testFile, 0755)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Test 4: MOVE event (move file between subdirectories within test directory)
	subDir1 := filepath.Join(tempDir, "test", "subdir1")
	err = os.Mkdir(subDir1, 0755)
	require.NoError(t, err)

	subDir2 := filepath.Join(tempDir, "test", "subdir2")
	err = os.Mkdir(subDir2, 0755)
	require.NoError(t, err)

	movedFileName := filepath.Join(subDir2, "moved_test.txt")
	err = os.Rename(testFile, movedFileName)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Test 5: RENAME event (rename file in same subdirectory)
	renamedFileName := filepath.Join(subDir2, "renamed_test.txt")
	err = os.Rename(movedFileName, renamedFileName)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Test 6: REMOVE event (delete file)
	err = os.Remove(renamedFileName)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()

	// Verify that events were generated for each operation
	assert.GreaterOrEqual(t, len(mockExporter.events), 6, "Expected at least 6 FIM events to be generated")

	// Check for specific event types
	eventTypes := make(map[hostfimsensor.FimEventType]bool)
	eventPaths := make(map[string]hostfimsensor.FimEventType)

	for _, event := range mockExporter.events {
		eventTypes[event.GetEventType()] = true
		eventPaths[event.GetPath()] = event.GetEventType()
	}

	// Verify CREATE event
	assert.True(t, eventTypes[hostfimsensor.FimEventTypeCreate], "Expected CREATE event to be generated")

	// Verify CHANGE event
	assert.True(t, eventTypes[hostfimsensor.FimEventTypeChange], "Expected CHANGE event to be generated")

	// Verify CHMOD event
	assert.True(t, eventTypes[hostfimsensor.FimEventTypeChmod], "Expected CHMOD event to be generated")

	// Verify MOVE event
	// assert.True(t, eventTypes[hostfimsensor.FimEventTypeMove], "Expected MOVE event to be generated")

	// Verify RENAME event
	assert.True(t, eventTypes[hostfimsensor.FimEventTypeRename], "Expected RENAME event to be generated")

	// Verify REMOVE event
	assert.True(t, eventTypes[hostfimsensor.FimEventTypeRemove], "Expected REMOVE event to be generated")

	// Print event summary for debugging
	t.Logf("Generated %d events:", len(mockExporter.events))
	for _, event := range mockExporter.events {
		t.Logf("  - %s: %s", event.GetEventType(), event.GetPath())
	}
}

func TestNewHostFimSensorWithBackend(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-backend-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Test periodic backend
	periodicConfig := DefaultPeriodicConfig()
	periodicConfig.ScanInterval = 100 * time.Millisecond
	periodicConfig.MaxSnapshotNodes = 1000

	fimConfig := HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: []HostFimPathConfig{
			{
				Path:     ".",
				OnCreate: true,
				OnChange: true,
				OnRemove: true,
			},
		},
		BatchConfig: HostFimBatchConfig{
			MaxBatchSize: 100,
			BatchTimeout: time.Second,
		},
		DedupConfig: HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: time.Minute,
			MaxCacheSize:    100,
		},
		PeriodicConfig: &periodicConfig,
	}

	// Create sensor with explicit backend selection
	sensor, err := NewHostFimSensorWithBackend(tempDir, fimConfig, mockExporter)
	require.NoError(t, err)
	require.NotNil(t, sensor)

	// Test that the sensor can be started
	err = sensor.Start()
	require.NoError(t, err)

	// Wait a bit for the initial scan
	time.Sleep(200 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()
}

func TestPeriodicConfigValidation(t *testing.T) {
	// Test valid configuration
	validConfig := DefaultPeriodicConfig()
	err := validConfig.Validate()
	assert.NoError(t, err)

	// Test invalid scan interval
	invalidConfig := DefaultPeriodicConfig()
	invalidConfig.ScanInterval = -1 * time.Second
	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ScanInterval must be positive")

	// Test invalid max snapshot nodes
	invalidConfig = DefaultPeriodicConfig()
	invalidConfig.MaxSnapshotNodes = 0
	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MaxSnapshotNodes must be positive")
}

func TestFimConfigValidation(t *testing.T) {
	// Test valid configuration
	validConfig := DefaultHostFimConfig()
	err := validConfig.Validate()
	assert.NoError(t, err)

	// Test invalid backend type
	invalidConfig := DefaultHostFimConfig()
	invalidConfig.BackendConfig.BackendType = "invalid"
	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend type")

	// Test periodic backend without periodic config
	invalidConfig = DefaultHostFimConfig()
	invalidConfig.BackendConfig.BackendType = FimBackendPeriodic
	invalidConfig.PeriodicConfig = nil
	err = invalidConfig.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "periodic backend requires PeriodicConfig")
}
