package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockProfileCreator implements ProfileCreator for testing
type MockProfileCreator struct {
	CreatedProfiles []*v1beta1.ContainerProfile
	ShouldFail      bool
	FailCount       int
	CallCount       int
}

func (m *MockProfileCreator) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	m.CallCount++

	if m.ShouldFail {
		if m.FailCount > 0 {
			m.FailCount--
			return fmt.Errorf("mock creation failed")
		}
		// If FailCount is 0 but ShouldFail is true, continue failing (unless FailCount was initially set)
		// This allows for "fail N times then succeed" behavior
		if m.FailCount == 0 && m.CallCount <= 1 {
			// This means ShouldFail was set but no specific FailCount, so always fail
			return fmt.Errorf("mock always fails")
		}
	}

	m.CreatedProfiles = append(m.CreatedProfiles, profile)
	return nil
}

func TestQueueBasicOperations(t *testing.T) {
	// Create temporary directory for test queue
	tempDir, err := os.MkdirTemp("", "queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create mock creator
	mockCreator := &MockProfileCreator{}

	// Create queue with fast retry interval for testing
	config := QueueConfig{
		QueueName:       "test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    5,
		RetryInterval:   100 * time.Millisecond, // Fast for testing
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	// Test enqueue
	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "default",
		},
	}

	err = queueData.Enqueue(profile)
	if err != nil {
		t.Fatalf("Failed to enqueue profile: %v", err)
	}

	// Check queue size
	if queueData.GetQueueSize() != 1 {
		t.Errorf("Expected queue size 1, got %d", queueData.GetQueueSize())
	}

	// Start processing
	queueData.Start()

	// Wait for processing
	time.Sleep(150 * time.Millisecond)

	// Check that profile was created
	if len(mockCreator.CreatedProfiles) != 1 {
		t.Errorf("Expected 1 created profile, got %d", len(mockCreator.CreatedProfiles))
	}

	// Check queue is empty after successful processing
	if queueData.GetQueueSize() != 0 {
		t.Errorf("Expected queue size 0 after processing, got %d", queueData.GetQueueSize())
	}
}

func TestQueueLRUEviction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-lru-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true} // Make it fail so items stay in queue

	config := QueueConfig{
		QueueName:       "lru-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    3, // Small size to test LRU
		RetryInterval:   1 * time.Second,
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	// Add more items than max size
	for i := 0; i < 5; i++ {
		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-profile-%d", i),
				Namespace: "default",
			},
		}
		err = queueData.Enqueue(profile)
		if err != nil {
			t.Fatalf("Failed to enqueue profile %d: %v", i, err)
		}
	}

	// Queue should be limited to max size
	if queueData.GetQueueSize() != 3 {
		t.Errorf("Expected queue size 3 due to LRU eviction, got %d", queueData.GetQueueSize())
	}
}

func TestQueueRetryMechanism(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-retry-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Mock that fails twice then succeeds
	mockCreator := &MockProfileCreator{
		ShouldFail: true,
		FailCount:  2, // Will fail 2 times, then succeed
	}

	config := QueueConfig{
		QueueName:       "retry-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    10,
		RetryInterval:   50 * time.Millisecond, // Fast for testing
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "retry-test-profile",
			Namespace: "default",
		},
	}

	err = queueData.Enqueue(profile)
	if err != nil {
		t.Fatalf("Failed to enqueue profile: %v", err)
	}

	queueData.Start()

	// Wait for multiple retry attempts - need more time for 3 attempts
	time.Sleep(300 * time.Millisecond)

	// Should have been called at least 3 times (2 failures + 1 success)
	if mockCreator.CallCount < 3 {
		t.Errorf("Expected at least 3 calls (2 failures + 1 success), got %d", mockCreator.CallCount)
	}

	// Should eventually succeed
	if len(mockCreator.CreatedProfiles) != 1 {
		t.Errorf("Expected 1 successfully created profile, got %d", len(mockCreator.CreatedProfiles))
	}

	// Queue should be empty after success
	if queueData.GetQueueSize() != 0 {
		t.Errorf("Expected queue size 0 after successful retry, got %d", queueData.GetQueueSize())
	}
}

func TestQueuePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-persistence-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true} // Don't process items in first queue

	config := QueueConfig{
		QueueName:       "persistence-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    10,
		RetryInterval:   1 * time.Second,
		ItemsPerSegment: 10,
	}

	// Create first queue and add items
	queueData1, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create first queue: %v", err)
	}

	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "persistence-test-profile",
			Namespace: "default",
		},
	}

	err = queueData1.Enqueue(profile)
	if err != nil {
		t.Fatalf("Failed to enqueue profile: %v", err)
	}

	if queueData1.GetQueueSize() != 1 {
		t.Errorf("Expected queue size 1, got %d", queueData1.GetQueueSize())
	}

	// Close first queue WITHOUT starting processing
	queueData1.Close()

	// Create second queue with same config (should load from disk)
	mockCreator2 := &MockProfileCreator{} // This one will succeed
	queueData2, err := NewQueueData(context.Background(), mockCreator2, config)
	if err != nil {
		t.Fatalf("Failed to create second queue: %v", err)
	}
	defer queueData2.Close()

	// Should have loaded the item from disk
	if queueData2.GetQueueSize() != 1 {
		t.Errorf("Expected queue size 1 after reload, got %d", queueData2.GetQueueSize())
	}

	// Start processing to verify the item is correct
	queueData2.Start()

	// Wait longer for processing since retry interval is 1 second
	time.Sleep(1200 * time.Millisecond)

	// Should have processed the persisted item
	if len(mockCreator2.CreatedProfiles) != 1 {
		t.Errorf("Expected 1 created profile after reload, got %d", len(mockCreator2.CreatedProfiles))
		return // Avoid panic on next line
	}

	if mockCreator2.CreatedProfiles[0].Name != "persistence-test-profile" {
		t.Errorf("Expected profile name 'persistence-test-profile', got '%s'", mockCreator2.CreatedProfiles[0].Name)
	}
}

func TestQueueStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-stats-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true}

	config := QueueConfig{
		QueueName:       "stats-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    10,
		RetryInterval:   1 * time.Second,
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	// Add some items
	for i := 0; i < 3; i++ {
		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("stats-test-profile-%d", i),
				Namespace: "default",
			},
		}
		err = queueData.Enqueue(profile)
		if err != nil {
			t.Fatalf("Failed to enqueue profile %d: %v", i, err)
		}
	}

	stats := queueData.GetQueueStats()

	// Check stats
	if stats["size"] != 3 {
		t.Errorf("Expected size 3 in stats, got %v", stats["size"])
	}

	if stats["maxQueueSize"] != 10 {
		t.Errorf("Expected maxQueueSize 10 in stats, got %v", stats["maxQueueSize"])
	}

	if stats["retryInterval"] != "1s" {
		t.Errorf("Expected retryInterval '1s' in stats, got %v", stats["retryInterval"])
	}

	if stats["running"] != true {
		t.Errorf("Expected running true in stats, got %v", stats["running"])
	}
}

func TestQueueEmptyOperation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-empty-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true}

	config := QueueConfig{
		QueueName:       "empty-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    10,
		RetryInterval:   1 * time.Second,
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	// Add some items
	for i := 0; i < 5; i++ {
		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("empty-test-profile-%d", i),
				Namespace: "default",
			},
		}
		err = queueData.Enqueue(profile)
		if err != nil {
			t.Fatalf("Failed to enqueue profile %d: %v", i, err)
		}
	}

	if queueData.GetQueueSize() != 5 {
		t.Errorf("Expected queue size 5 before empty, got %d", queueData.GetQueueSize())
	}

	// Empty the queue
	err = queueData.EmptyQueue()
	if err != nil {
		t.Fatalf("Failed to empty queue: %v", err)
	}

	if queueData.GetQueueSize() != 0 {
		t.Errorf("Expected queue size 0 after empty, got %d", queueData.GetQueueSize())
	}
}

func TestQueueConcurrentOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-concurrent-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{}

	config := QueueConfig{
		QueueName:       "concurrent-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    100,
		RetryInterval:   50 * time.Millisecond,
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	queueData.Start()

	// Concurrently enqueue items
	numGoroutines := 10
	itemsPerGoroutine := 5
	done := make(chan bool, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for i := 0; i < itemsPerGoroutine; i++ {
				profile := &v1beta1.ContainerProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("concurrent-profile-%d-%d", goroutineID, i),
						Namespace: "default",
					},
				}

				err := queueData.Enqueue(profile)
				if err != nil {
					t.Errorf("Failed to enqueue profile from goroutine %d: %v", goroutineID, err)
				}
			}
		}(g)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Check that all items were processed
	expectedTotal := numGoroutines * itemsPerGoroutine
	if len(mockCreator.CreatedProfiles) != expectedTotal {
		t.Errorf("Expected %d created profiles, got %d", expectedTotal, len(mockCreator.CreatedProfiles))
	}

	// Queue should be empty after processing
	if queueData.GetQueueSize() != 0 {
		t.Errorf("Expected queue size 0 after processing, got %d", queueData.GetQueueSize())
	}
}

func TestQueueStopAndRestart(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "queue-stop-restart-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true}

	config := QueueConfig{
		QueueName:       "stop-restart-test-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    10,
		RetryInterval:   100 * time.Millisecond,
		ItemsPerSegment: 10,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Add an item
	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "stop-restart-profile",
			Namespace: "default",
		},
	}

	err = queueData.Enqueue(profile)
	if err != nil {
		t.Fatalf("Failed to enqueue profile: %v", err)
	}

	// Start processing
	queueData.Start()
	time.Sleep(50 * time.Millisecond)

	// Stop the queue
	err = queueData.Close()
	if err != nil {
		t.Fatalf("Failed to close queue: %v", err)
	}

	// Verify queue is stopped
	err = queueData.Enqueue(profile)
	if err == nil {
		t.Error("Expected error when enqueueing to stopped queue, got nil")
	}
}

func TestQueueWithDifferentConfigurations(t *testing.T) {
	testCases := []struct {
		name   string
		config QueueConfig
	}{
		{
			name: "small-queue",
			config: QueueConfig{
				QueueName:       "small-queue",
				MaxQueueSize:    2,
				RetryInterval:   50 * time.Millisecond,
				ItemsPerSegment: 5,
			},
		},
		{
			name: "large-queue",
			config: QueueConfig{
				QueueName:       "large-queue",
				MaxQueueSize:    1000,
				RetryInterval:   10 * time.Millisecond,
				ItemsPerSegment: 100,
			},
		},
		{
			name: "fast-retry",
			config: QueueConfig{
				QueueName:       "fast-retry-queue",
				MaxQueueSize:    10,
				RetryInterval:   10 * time.Millisecond,
				ItemsPerSegment: 10,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("queue-config-test-%s", tc.name))
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			tc.config.QueueDir = tempDir
			mockCreator := &MockProfileCreator{}

			queueData, err := NewQueueData(context.Background(), mockCreator, tc.config)
			if err != nil {
				t.Fatalf("Failed to create queue with config %s: %v", tc.name, err)
			}
			defer queueData.Close()

			// Test basic functionality
			profile := &v1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("config-test-profile-%s", tc.name),
					Namespace: "default",
				},
			}

			err = queueData.Enqueue(profile)
			if err != nil {
				t.Fatalf("Failed to enqueue profile with config %s: %v", tc.name, err)
			}

			queueData.Start()

			// Wait based on retry interval
			time.Sleep(tc.config.RetryInterval + 50*time.Millisecond)

			if len(mockCreator.CreatedProfiles) != 1 {
				t.Errorf("Expected 1 created profile with config %s, got %d", tc.name, len(mockCreator.CreatedProfiles))
			}
		})
	}
}

// Benchmark tests
func BenchmarkQueueEnqueue(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "queue-benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{ShouldFail: true} // Don't process items

	config := QueueConfig{
		QueueName:       "benchmark-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    100000, // Large size for benchmarking
		RetryInterval:   1 * time.Second,
		ItemsPerSegment: 1000,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		b.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	profile := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "benchmark-profile",
			Namespace: "default",
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			queueData.Enqueue(profile)
		}
	})
}

func BenchmarkQueueProcessing(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "queue-processing-benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCreator := &MockProfileCreator{}

	config := QueueConfig{
		QueueName:       "processing-benchmark-queue",
		QueueDir:        tempDir,
		MaxQueueSize:    b.N + 1000,
		RetryInterval:   1 * time.Millisecond, // Very fast for benchmarking
		ItemsPerSegment: 1000,
	}

	queueData, err := NewQueueData(context.Background(), mockCreator, config)
	if err != nil {
		b.Fatalf("Failed to create queue: %v", err)
	}
	defer queueData.Close()

	// Pre-populate queue
	for i := 0; i < b.N; i++ {
		profile := &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("benchmark-profile-%d", i),
				Namespace: "default",
			},
		}
		queueData.Enqueue(profile)
	}

	b.ResetTimer()
	queueData.Start()

	// Wait for all items to be processed
	for queueData.GetQueueSize() > 0 {
		time.Sleep(1 * time.Millisecond)
	}
}
