package hostfimsensor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
)

// mockExporter implements the exporters.Exporter interface for testing.
type mockExporter struct {
	mu        sync.Mutex
	fimEvents []fimtypes.FimEvent
}

func (m *mockExporter) SendRuleAlert(_ ruleengine.RuleFailure)          {}
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

	sensor := NewHostFimSensorWithBatching(tmpDir, pathConfigs, mockExp, batchConfig)
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
			if evt.GetPath() == testFile && evt.GetEventType() == fimtypes.FimEventTypeCreate {
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

func TestHostFimSensor_ConvertFsnotifyEventToFimEvent(t *testing.T) {
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

	sensor := NewHostFimSensor(tmpDir, pathConfigs, mockExp).(*HostFimSensorImpl)

	testCases := []struct {
		name         string
		fsnotifyOp   fsnotify.Op
		expectedType fimtypes.FimEventType
		expectedPath string
	}{
		{
			name:         "Create event",
			fsnotifyOp:   fsnotify.Create,
			expectedType: fimtypes.FimEventTypeCreate,
			expectedPath: "/test/path/file.txt",
		},
		{
			name:         "Write event",
			fsnotifyOp:   fsnotify.Write,
			expectedType: fimtypes.FimEventTypeChange,
			expectedPath: "/test/path/file.txt",
		},
		{
			name:         "Remove event",
			fsnotifyOp:   fsnotify.Remove,
			expectedType: fimtypes.FimEventTypeRemove,
			expectedPath: "/test/path/file.txt",
		},
		{
			name:         "Rename event",
			fsnotifyOp:   fsnotify.Rename,
			expectedType: fimtypes.FimEventTypeRename,
			expectedPath: "/test/path/file.txt",
		},
		{
			name:         "Chmod event",
			fsnotifyOp:   fsnotify.Chmod,
			expectedType: fimtypes.FimEventTypeChmod,
			expectedPath: "/test/path/file.txt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := fsnotify.Event{
				Name: tc.expectedPath,
				Op:   tc.fsnotifyOp,
			}

			fimEvent := sensor.convertFsnotifyEventToFimEvent(event)

			if fimEvent.GetPath() != tc.expectedPath {
				t.Errorf("expected path %s, got %s", tc.expectedPath, fimEvent.GetPath())
			}

			if fimEvent.GetEventType() != tc.expectedType {
				t.Errorf("expected event type %s, got %s", tc.expectedType, fimEvent.GetEventType())
			}

			if fimEvent.GetTimestamp().IsZero() {
				t.Error("expected timestamp to be set, but it was zero")
			}
		})
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

		sensor := NewHostFimSensorWithBatching(tmpDir, pathConfigs, mockExp, batchConfig)
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

		sensor := NewHostFimSensorWithBatching(tmpDir, pathConfigs, mockExp, batchConfig)
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

		sensor := NewHostFimSensorWithBatching(tmpDir, pathConfigs, mockExp, batchConfig)
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

func TestHostFimSensor_Deduplication(t *testing.T) {
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

	// Test de-duplication with short time window
	t.Run("DeduplicationEnabled", func(t *testing.T) {
		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 1,                      // Send immediately
			BatchTimeout: 100 * time.Millisecond, // Short timeout
		}

		dedupConfig := HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: 500 * time.Millisecond, // Short time window for testing
			MaxCacheSize:    100,
		}

		sensor := NewHostFimSensorWithConfig(tmpDir, pathConfigs, mockExp, batchConfig, dedupConfig)
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		testFile := filepath.Join(tmpDir, "dedup_test.txt")

		// Create file first time
		f, err := os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for first event
		time.Sleep(200 * time.Millisecond)

		// Write to file (change operation)
		f, err = os.OpenFile(testFile, os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("failed to open test file: %v", err)
		}
		f.WriteString("test content")
		f.Close()

		// Wait for second event
		time.Sleep(200 * time.Millisecond)

		// Write to file again (should be duplicate change operation)
		f, err = os.OpenFile(testFile, os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("failed to open test file: %v", err)
		}
		f.WriteString("more content")
		f.Close()

		// Wait for potential third event
		time.Sleep(200 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		// Debug: print event details
		for i, evt := range mockExp.fimEvents {
			t.Logf("Event %d: Path=%s, Type=%s", i, evt.GetPath(), evt.GetEventType())
		}
		mockExp.mu.Unlock()

		// We expect 2 events: 1 create + 1 change (the second change should be duplicate)
		if eventCount != 2 {
			t.Errorf("expected 2 events (create + 1 change, duplicate should be filtered), got %d", eventCount)
		}
	})

	// Test de-duplication disabled
	t.Run("DeduplicationDisabled", func(t *testing.T) {
		// Clear mock exporter
		mockExp.mu.Lock()
		mockExp.fimEvents = mockExp.fimEvents[:0]
		mockExp.mu.Unlock()

		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 1,                      // Send immediately
			BatchTimeout: 100 * time.Millisecond, // Short timeout
		}

		dedupConfig := HostFimDedupConfig{
			DedupEnabled:    false, // Disable de-duplication
			DedupTimeWindow: 500 * time.Millisecond,
			MaxCacheSize:    100,
		}

		sensor := NewHostFimSensorWithConfig(tmpDir, pathConfigs, mockExp, batchConfig, dedupConfig)
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		testFile := filepath.Join(tmpDir, "no_dedup_test.txt")

		// Create file first time
		f, err := os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for first event
		time.Sleep(200 * time.Millisecond)

		// Create file again (should NOT be duplicate since dedup is disabled)
		f, err = os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for second event
		time.Sleep(200 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 2 {
			t.Errorf("expected 2 events (no dedup), got %d", eventCount)
		}
	})

	// Test different operations on same file
	t.Run("DifferentOperations", func(t *testing.T) {
		// Clear mock exporter
		mockExp.mu.Lock()
		mockExp.fimEvents = mockExp.fimEvents[:0]
		mockExp.mu.Unlock()

		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 1,                      // Send immediately
			BatchTimeout: 100 * time.Millisecond, // Short timeout
		}

		dedupConfig := HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: 500 * time.Millisecond,
			MaxCacheSize:    100,
		}

		sensor := NewHostFimSensorWithConfig(tmpDir, pathConfigs, mockExp, batchConfig, dedupConfig)
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		testFile := filepath.Join(tmpDir, "multi_op_test.txt")

		// Create file
		f, err := os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for create event
		time.Sleep(200 * time.Millisecond)

		// Write to file (different operation)
		f, err = os.OpenFile(testFile, os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("failed to open test file: %v", err)
		}
		f.WriteString("test content")
		f.Close()

		// Wait for write event
		time.Sleep(200 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 2 {
			t.Errorf("expected 2 events (create + write), got %d", eventCount)
		}
	})

	// Test time window expiration
	t.Run("TimeWindowExpiration", func(t *testing.T) {
		// Clear mock exporter
		mockExp.mu.Lock()
		mockExp.fimEvents = mockExp.fimEvents[:0]
		mockExp.mu.Unlock()

		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 1,                      // Send immediately
			BatchTimeout: 100 * time.Millisecond, // Short timeout
		}

		dedupConfig := HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: 300 * time.Millisecond, // Short time window
			MaxCacheSize:    100,
		}

		sensor := NewHostFimSensorWithConfig(tmpDir, pathConfigs, mockExp, batchConfig, dedupConfig)
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		testFile := filepath.Join(tmpDir, "expire_test.txt")

		// Create file first time
		f, err := os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for first event
		time.Sleep(200 * time.Millisecond)

		// Wait for time window to expire
		time.Sleep(400 * time.Millisecond)

		// Create file again (should NOT be duplicate since time window expired)
		f, err = os.Create(testFile)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
		f.Close()

		// Wait for second event
		time.Sleep(200 * time.Millisecond)

		mockExp.mu.Lock()
		eventCount := len(mockExp.fimEvents)
		mockExp.mu.Unlock()

		if eventCount != 2 {
			t.Errorf("expected 2 events (time window expired), got %d", eventCount)
		}
	})

	// Test de-duplication with manual event simulation
	t.Run("ManualDeduplication", func(t *testing.T) {
		batchConfig := HostFimBatchConfig{
			MaxBatchSize: 1,                      // Send immediately
			BatchTimeout: 100 * time.Millisecond, // Short timeout
		}

		dedupConfig := HostFimDedupConfig{
			DedupEnabled:    true,
			DedupTimeWindow: 500 * time.Millisecond,
			MaxCacheSize:    100,
		}

		sensor := NewHostFimSensorWithConfig(tmpDir, pathConfigs, mockExp, batchConfig, dedupConfig).(*HostFimSensorImpl)
		if err := sensor.Start(); err != nil {
			t.Fatalf("failed to start HostFimSensor: %v", err)
		}
		defer sensor.Stop()

		testFile := filepath.Join(tmpDir, "manual_dedup_test.txt")

		// Simulate first event
		event1 := fsnotify.Event{
			Name: testFile,
			Op:   fsnotify.Create,
		}
		fimEvent1 := sensor.convertFsnotifyEventToFimEvent(event1)

		// Check if first event is duplicate (should not be)
		if sensor.dedupCache.isDuplicate(fimEvent1.GetPath(), fimEvent1.GetEventType()) {
			t.Error("First event should not be duplicate")
		}

		// Simulate second event (same file, same operation)
		event2 := fsnotify.Event{
			Name: testFile,
			Op:   fsnotify.Create,
		}
		fimEvent2 := sensor.convertFsnotifyEventToFimEvent(event2)

		// Check if second event is duplicate (should be)
		if !sensor.dedupCache.isDuplicate(fimEvent2.GetPath(), fimEvent2.GetEventType()) {
			t.Error("Second event should be duplicate")
		}

		// Simulate third event (same file, different operation)
		event3 := fsnotify.Event{
			Name: testFile,
			Op:   fsnotify.Write,
		}
		fimEvent3 := sensor.convertFsnotifyEventToFimEvent(event3)

		// Check if third event is duplicate (should not be, different operation)
		if sensor.dedupCache.isDuplicate(fimEvent3.GetPath(), fimEvent3.GetEventType()) {
			t.Error("Third event should not be duplicate (different operation)")
		}
	})
}

func TestDedupCache_Logic(t *testing.T) {
	// Test the de-duplication cache logic directly
	dedupCache := &dedupCache{
		cache:      make(map[string]time.Time),
		maxSize:    100,
		timeWindow: 500 * time.Millisecond,
	}

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
