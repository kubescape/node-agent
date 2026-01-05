//go:build linux
// +build linux

package hostfimsensor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

// mockExporter implements the exporters.Exporter interface for testing.
type mockExporter struct {
	mu        sync.Mutex
	fimEvents []fimtypes.FimEvent
}

func (m *mockExporter) SendRuleAlert(_ types.RuleFailure)               {}
func (m *mockExporter) SendMalwareAlert(_ malwaremanager.MalwareResult) {}
func (m *mockExporter) SendFimAlerts(events []fimtypes.FimEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fimEvents = append(m.fimEvents, events...)
}

func TestHostFimSensor_CreateFileTriggersExporter(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile.txt")

	mockExp := &mockExporter{}
	pathConfigs := []HostFimPathConfig{
		{
			Path:     ".", // Use relative path since hostPath will be the tmpDir
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
			OnRename: true,
			OnChmod:  true,
			OnMove:   true,
		},
	}

	// Use custom batch config for testing with small batch size and timeout
	batchConfig := HostFimBatchConfig{
		MaxBatchSize: 1,                      // Send immediately when batch size is 1
		BatchTimeout: 100 * time.Millisecond, // Short timeout for testing
	}

	sensor, err := NewHostFimSensorWithBackend(tmpDir, HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: pathConfigs,
		BatchConfig: batchConfig,
		PeriodicConfig: &HostFimPeriodicConfig{
			ScanInterval:     100 * time.Millisecond,
			MaxScanDepth:     5,
			MaxSnapshotNodes: 1000,
			IncludeHidden:    false,
			ExcludePatterns:  []string{},
			MaxFileSize:      1024 * 1024,
			FollowSymlinks:   false,
		},
	}, mockExp)
	if err != nil {
		t.Fatalf("failed to create HostFimSensor: %v", err)
	}
	if err := sensor.Start(); err != nil {
		t.Fatalf("failed to start HostFimSensor: %v", err)
	}
	defer sensor.Stop()

	// Create a file to trigger the event
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	f.Close()

	found := false
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		mockExp.mu.Lock()
		for _, evt := range mockExp.fimEvents {
			// The FIM event path is relative to the host path, so we need to compare accordingly
			expectedRelativePath := "/testfile.txt" // Since pathConfig.Path is ".", the relative path is just the filename
			if evt.GetPath() == expectedRelativePath && evt.GetEventType() == fimtypes.FimEventTypeCreate {
				found = true
				break
			}
		}
		mockExp.mu.Unlock()
		if found {
			break
		}
	}
	if !found {
		t.Errorf("expected FIM event for file creation, but none was received")
	}
}

func TestHostFimSensor_CreateNestedFileTriggersExporter(t *testing.T) {
	tmpDir := t.TempDir()
	os.Mkdir(filepath.Join(tmpDir, "testdir"), 0755)
	testFile := filepath.Join(tmpDir, "testdir", "testfile.txt")

	mockExp := &mockExporter{}
	pathConfigs := []HostFimPathConfig{
		{
			Path:     "testdir", // Use relative path since hostPath will be the tmpDir
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
			OnRename: true,
			OnChmod:  true,
			OnMove:   true,
		},
	}

	// Use custom batch config for testing with small batch size and timeout
	batchConfig := HostFimBatchConfig{
		MaxBatchSize: 1,                      // Send immediately when batch size is 1
		BatchTimeout: 100 * time.Millisecond, // Short timeout for testing
	}

	sensor, err := NewHostFimSensorWithBackend(tmpDir, HostFimConfig{
		BackendConfig: HostFimBackendConfig{
			BackendType: FimBackendPeriodic,
		},
		PathConfigs: pathConfigs,
		BatchConfig: batchConfig,
		PeriodicConfig: &HostFimPeriodicConfig{
			ScanInterval:     100 * time.Millisecond,
			MaxScanDepth:     5,
			MaxSnapshotNodes: 1000,
			IncludeHidden:    false,
			ExcludePatterns:  []string{},
			MaxFileSize:      1024 * 1024,
			FollowSymlinks:   false,
		},
	}, mockExp)
	if err != nil {
		t.Fatalf("failed to create HostFimSensor: %v", err)
	}
	if err := sensor.Start(); err != nil {
		t.Fatalf("failed to start HostFimSensor: %v", err)
	}
	defer sensor.Stop()

	// Create a file to trigger the event
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	f.Close()

	// Wait for the event to be picked up (fsnotify is async)
	found := false
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		mockExp.mu.Lock()
		for _, evt := range mockExp.fimEvents {
			t.Logf("FIM event: %s", evt.GetPath())
			// The FIM event path is relative to the host path, so we need to compare accordingly
			expectedRelativePath := "/testdir/testfile.txt" // Since pathConfig.Path is "testdir", the relative path includes the subdirectory
			if evt.GetPath() == expectedRelativePath && evt.GetEventType() == fimtypes.FimEventTypeCreate {
				found = true
				break
			}
		}
		mockExp.mu.Unlock()
		if found {
			break
		}
	}
	if !found {
		t.Errorf("expected FIM event for file creation, but none was received")
	}
}

func TestHostFimSensor_Batching(t *testing.T) {
	tmpDir := t.TempDir()
	mockExp := &mockExporter{}
	pathConfigs := []HostFimPathConfig{
		{
			Path:     ".",
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
			OnRename: true,
			OnChmod:  true,
			OnMove:   true,
		},
	}

	// Test batch size-based sending
	t.Run("BatchSizeBased", func(t *testing.T) {
		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 3,                // Send when 3 events are collected
			BatchTimeout: 10 * time.Second, // Long timeout to test size-based sending
		}

		sensor, err := NewHostFimSensorWithBackend(tmpDir, HostFimConfig{
			BackendConfig: HostFimBackendConfig{
				BackendType: FimBackendPeriodic,
			},
			PathConfigs: pathConfigs,
			BatchConfig: batchConfig,
			PeriodicConfig: &HostFimPeriodicConfig{
				ScanInterval:     100 * time.Millisecond,
				MaxScanDepth:     5,
				MaxSnapshotNodes: 1000,
				IncludeHidden:    false,
				ExcludePatterns:  []string{},
				MaxFileSize:      1024 * 1024,
				FollowSymlinks:   false,
			},
		}, mockExp)
		if err != nil {
			t.Fatalf("failed to create HostFimSensor: %v", err)
		}
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		// Create 3 files to trigger batch sending
		for i := 0; i < 3; i++ {
			testFile := filepath.Join(tmpDir, fmt.Sprintf("testfile%d.txt", i))
			f, err := os.Create(testFile)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}
			f.Close()
		}

		// Wait for the batch to be sent
		time.Sleep(500 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 3 {
			t.Errorf("expected 3 events in batch, got %d", eventCount)
		}
	})

	// Test timeout-based sending
	t.Run("TimeoutBased", func(t *testing.T) {
		// Clear mock exporter
		mockExp.mu.Lock()
		mockExp.fimEvents = mockExp.fimEvents[:0]
		mockExp.mu.Unlock()

		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 10,                     // Large batch size
			BatchTimeout: 200 * time.Millisecond, // Short timeout
		}

		sensor, err := NewHostFimSensorWithBackend(tmpDir, HostFimConfig{
			BackendConfig: HostFimBackendConfig{
				BackendType: FimBackendPeriodic,
			},
			PathConfigs: pathConfigs,
			BatchConfig: batchConfig,
			PeriodicConfig: &HostFimPeriodicConfig{
				ScanInterval:     100 * time.Millisecond,
				MaxScanDepth:     5,
				MaxSnapshotNodes: 1000,
				IncludeHidden:    false,
				ExcludePatterns:  []string{},
				MaxFileSize:      1024 * 1024,
				FollowSymlinks:   false,
			},
		}, mockExp)
		if err != nil {
			t.Fatalf("failed to create HostFimSensor: %v", err)
		}
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		// Create 1 file to trigger timeout-based sending
		testFile := filepath.Join(tmpDir, "timeout_test.txt")
		f, err := os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for timeout to trigger batch sending
		time.Sleep(300 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 1 {
			t.Errorf("expected 1 event from timeout, got %d", eventCount)
		}
	})

	// Test parallel sending
	t.Run("ParallelSending", func(t *testing.T) {
		// Clear mock exporter
		mockExp.mu.Lock()
		mockExp.fimEvents = mockExp.fimEvents[:0]
		mockExp.mu.Unlock()

		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 2,               // Small batch size
			BatchTimeout: 1 * time.Second, // Medium timeout
		}

		sensor, err := NewHostFimSensorWithBackend(tmpDir, HostFimConfig{
			BackendConfig: HostFimBackendConfig{
				BackendType: FimBackendPeriodic,
			},
			PathConfigs: pathConfigs,
			BatchConfig: batchConfig,
			PeriodicConfig: &HostFimPeriodicConfig{
				ScanInterval:     100 * time.Millisecond,
				MaxScanDepth:     5,
				MaxSnapshotNodes: 1000,
				IncludeHidden:    false,
				ExcludePatterns:  []string{},
				MaxFileSize:      1024 * 1024,
				FollowSymlinks:   false,
			},
		}, mockExp)
		if err != nil {
			t.Fatalf("failed to create HostFimSensor: %v", err)
		}
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		// Create 4 files rapidly to test parallel batch sending
		for i := 0; i < 4; i++ {
			testFile := filepath.Join(tmpDir, fmt.Sprintf("parallel_test%d.txt", i))
			f, err := os.Create(testFile)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}
			f.Close()
		}

		// Wait for batches to be sent
		time.Sleep(500 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 4 {
			t.Errorf("expected 4 events total, got %d", eventCount)
		}
	})
}

func TestDedupCache_Logic(t *testing.T) {
	// Test the de-duplication cache logic directly
	dedupCache := newDedupCache(500*time.Millisecond, 100)

	path := "/test/file.txt"
	operation := fimtypes.FimEventTypeCreate

	// First call should not be duplicate
	if dedupCache.isDuplicate(path, operation) {
		t.Error("First call should not be duplicate")
	}

	// Second call within time window should be duplicate
	if !dedupCache.isDuplicate(path, operation) {
		t.Error("Second call within time window should be duplicate")
	}

	// Different operation on same path should not be duplicate
	if dedupCache.isDuplicate(path, fimtypes.FimEventTypeChange) {
		t.Error("Different operation should not be duplicate")
	}

	// Same operation on different path should not be duplicate
	if dedupCache.isDuplicate("/test/file2.txt", operation) {
		t.Error("Different path should not be duplicate")
	}

	// Wait for time window to expire
	time.Sleep(600 * time.Millisecond)

	// Call after time window should not be duplicate
	if dedupCache.isDuplicate(path, operation) {
		t.Error("Call after time window should not be duplicate")
	}
}
