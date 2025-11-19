package exporters

import (
	"sync"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func createTestAlert(containerID string, alertName string) apitypes.RuntimeAlert {
	return apitypes.RuntimeAlert{
		Message: alertName,
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID:   containerID,
			ContainerName: "test-container",
			PodName:       "test-pod",
			Namespace:     "test-ns",
		},
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: alertName,
			Timestamp: time.Now(),
		},
	}
}

func createTestProcessTree(pid uint32) apitypes.ProcessTree {
	return apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID:     pid,
			PPID:    1,
			Comm:    "test-process",
			Cmdline: "test-process --arg",
		},
	}
}

func TestContainerBulk_AddAlert(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 10 * time.Second,
	}

	alert := createTestAlert("container-123", "test-alert-1")
	processTree := createTestProcessTree(100)

	bulk.addAlert(alert, processTree, []string{"aws-s3"})

	assert.Equal(t, 1, len(bulk.alerts))
	assert.NotNil(t, bulk.rootProcess, "Root process should be set")
	assert.Equal(t, uint32(100), bulk.rootProcess.PID)
	assert.NotNil(t, bulk.processMap, "Process map should be initialized")
	assert.Equal(t, 1, len(bulk.processMap), "Should have 1 process in map")
	assert.Equal(t, []string{"aws-s3"}, bulk.cloudServices)
	assert.False(t, bulk.firstAlertTime.IsZero())
}

func TestContainerBulk_AddMultipleAlerts(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 10 * time.Second,
	}

	// Add first alert
	alert1 := createTestAlert("container-123", "test-alert-1")
	processTree1 := createTestProcessTree(100)
	bulk.addAlert(alert1, processTree1, []string{"aws-s3"})

	// Add second alert with different process
	alert2 := createTestAlert("container-123", "test-alert-2")
	processTree2 := createTestProcessTree(200)
	bulk.addAlert(alert2, processTree2, []string{"azure-blob", "aws-s3"})

	assert.Equal(t, 2, len(bulk.alerts))
	// Cloud services should be merged and deduplicated
	assert.Contains(t, bulk.cloudServices, "aws-s3")
	assert.Contains(t, bulk.cloudServices, "azure-blob")
	// Process map should contain both processes
	assert.Equal(t, 2, len(bulk.processMap), "Should have 2 processes in map")
}

func TestContainerBulk_ChainMerging(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 10 * time.Second,
	}

	// Create a chain: PID 1 (init) -> PID 10 (bash) -> PID 100 (curl)
	chain1 := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID:  1,
			PPID: 0,
			Comm: "init",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
				{PID: 10}: {
					PID:  10,
					PPID: 1,
					Comm: "bash",
					ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
						{PID: 100}: {
							PID:         100,
							PPID:        10,
							Comm:        "curl",
							ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
						},
					},
				},
			},
		},
	}

	alert1 := createTestAlert("container-123", "test-alert-1")
	bulk.addAlert(alert1, chain1, nil)

	// Verify first chain is added correctly
	assert.Equal(t, 3, len(bulk.processMap), "Should have 3 processes after first chain")
	assert.Equal(t, uint32(1), bulk.rootProcess.PID, "Root should be PID 1")

	// Create a second chain with a branch: PID 1 -> PID 10 -> PID 101 (wget)
	chain2 := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID:  1,
			PPID: 0,
			Comm: "init",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
				{PID: 10}: {
					PID:  10,
					PPID: 1,
					Comm: "bash",
					ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
						{PID: 101}: {
							PID:         101,
							PPID:        10,
							Comm:        "wget",
							ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
						},
					},
				},
			},
		},
	}

	alert2 := createTestAlert("container-123", "test-alert-2")
	bulk.addAlert(alert2, chain2, nil)

	// Verify branch is created correctly
	assert.Equal(t, 4, len(bulk.processMap), "Should have 4 processes after second chain (branch created)")
	assert.Equal(t, uint32(1), bulk.rootProcess.PID, "Root should still be PID 1")

	// Verify bash (PID 10) has two children (PID 100 and PID 101)
	bash := bulk.processMap[10]
	assert.NotNil(t, bash, "Bash process should exist")
	assert.Equal(t, 2, len(bash.ChildrenMap), "Bash should have 2 children")
	assert.NotNil(t, bash.ChildrenMap[apitypes.CommPID{PID: 100}], "Should have curl child")
	assert.NotNil(t, bash.ChildrenMap[apitypes.CommPID{PID: 101}], "Should have wget child")
}

func TestContainerBulk_ProcessEnrichment(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 10 * time.Second,
	}

	// First chain with minimal info
	chain1 := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID:         100,
			PPID:        1,
			Comm:        "bash",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
		},
	}

	alert1 := createTestAlert("container-123", "test-alert-1")
	bulk.addAlert(alert1, chain1, nil)

	// Second chain with additional info for same process
	chain2 := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			PID:         100,
			PPID:        1,
			Comm:        "bash",
			Path:        "/bin/bash",
			Cmdline:     "bash -c 'echo test'",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
		},
	}

	alert2 := createTestAlert("container-123", "test-alert-2")
	bulk.addAlert(alert2, chain2, nil)

	// Verify process was enriched, not duplicated
	assert.Equal(t, 1, len(bulk.processMap), "Should still have 1 process (enriched, not duplicated)")

	process := bulk.processMap[100]
	assert.Equal(t, "bash", process.Comm)
	assert.Equal(t, "/bin/bash", process.Path, "Path should be enriched")
	assert.Equal(t, "bash -c 'echo test'", process.Cmdline, "Cmdline should be enriched")
}

func TestContainerBulk_ShouldFlushSize(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0, 5),
		cloudServices:   make([]string, 0),
		maxSize:         5,
		timeoutDuration: 10 * time.Second,
	}

	// Add 4 alerts - should not flush
	for i := 0; i < 4; i++ {
		alert := createTestAlert("container-123", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		bulk.addAlert(alert, processTree, nil)
	}
	assert.False(t, bulk.shouldFlush(), "Should not flush with 4 alerts when max is 5")

	// Add 5th alert - should flush
	alert := createTestAlert("container-123", "test-alert")
	processTree := createTestProcessTree(105)
	bulk.addAlert(alert, processTree, nil)
	assert.True(t, bulk.shouldFlush(), "Should flush with 5 alerts when max is 5")
}

func TestContainerBulk_ShouldFlushTimeout(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 100 * time.Millisecond,
		firstAlertTime:  time.Now().Add(-200 * time.Millisecond), // Set to past
	}

	// Add one alert
	alert := createTestAlert("container-123", "test-alert")
	processTree := createTestProcessTree(100)
	bulk.addAlert(alert, processTree, nil)

	// Should flush due to timeout
	assert.True(t, bulk.shouldFlush(), "Should flush due to timeout")
}

func TestContainerBulk_Flush(t *testing.T) {
	bulk := &containerBulk{
		containerID:     "container-123",
		alerts:          make([]apitypes.RuntimeAlert, 0),
		cloudServices:   make([]string, 0),
		maxSize:         50,
		timeoutDuration: 10 * time.Second,
	}

	// Add alerts
	for i := 0; i < 3; i++ {
		alert := createTestAlert("container-123", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		bulk.addAlert(alert, processTree, []string{"service-" + string(rune(i))})
	}

	alerts, processTree, cloudServices := bulk.flush()

	assert.Equal(t, 3, len(alerts))
	assert.NotNil(t, processTree)
	assert.Greater(t, len(cloudServices), 0)

	// Bulk should be reset
	assert.Equal(t, 0, len(bulk.alerts))
	assert.Nil(t, bulk.rootProcess, "Root process should be cleared")
	assert.Nil(t, bulk.processMap, "Process map should be cleared")
	assert.Equal(t, 0, len(bulk.cloudServices))
	assert.True(t, bulk.firstAlertTime.IsZero())
}

func TestAlertBulkManager_AddAlert(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		return nil
	}

	manager := NewAlertBulkManager(50, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	alert := createTestAlert("container-123", "test-alert")
	processTree := createTestProcessTree(100)

	manager.AddAlert(alert, processTree, []string{"aws-s3"})

	assert.Equal(t, 1, manager.GetBulkCount())
}

func TestAlertBulkManager_FlushOnSizeLimit(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	var sentAlerts []apitypes.RuntimeAlert
	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		sentAlerts = alerts
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	containerID := "container-123"

	// Add 5 alerts - should trigger immediate flush
	for i := 0; i < 5; i++ {
		alert := createTestAlert(containerID, "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Give some time for flush to complete
	time.Sleep(100 * time.Millisecond)

	sendMutex.Lock()
	assert.Equal(t, 1, sendCount, "Should have sent one bulk")
	assert.Equal(t, 5, len(sentAlerts), "Should have sent 5 alerts")
	sendMutex.Unlock()

	// Bulk should be removed after flush
	assert.Equal(t, 0, manager.GetBulkCount())
}

func TestAlertBulkManager_FlushOnTimeout(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		return nil
	}

	manager := NewAlertBulkManager(50, 2, 0, 0, 0, 0, sendFunc) // 2 second timeout, use defaults for queue params
	manager.Start()
	defer manager.Stop()

	containerID := "container-123"

	// Add 1 alert
	alert := createTestAlert(containerID, "test-alert")
	processTree := createTestProcessTree(100)
	manager.AddAlert(alert, processTree, nil)

	assert.Equal(t, 1, manager.GetBulkCount())

	// Wait for timeout (2 seconds + 1 second check interval)
	time.Sleep(3500 * time.Millisecond)

	sendMutex.Lock()
	defer sendMutex.Unlock()
	assert.Equal(t, 1, sendCount, "Should have sent one bulk after timeout")
}

func TestAlertBulkManager_MultipleContainers(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	containerSends := make(map[string]int)

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		containerSends[containerID]++
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	// Add alerts for container 1
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-1", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Add alerts for container 2
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-2", "test-alert")
		processTree := createTestProcessTree(uint32(200 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Give some time for flush to complete
	time.Sleep(100 * time.Millisecond)

	sendMutex.Lock()
	assert.Equal(t, 2, sendCount, "Should have sent two bulks (one per container)")
	assert.Equal(t, 1, containerSends["container-1"])
	assert.Equal(t, 1, containerSends["container-2"])
	sendMutex.Unlock()
}

func TestAlertBulkManager_FlushContainer(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	var flushedContainerID string

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		flushedContainerID = containerID
		return nil
	}

	manager := NewAlertBulkManager(50, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	containerID := "container-123"

	// Add alerts
	for i := 0; i < 3; i++ {
		alert := createTestAlert(containerID, "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	assert.Equal(t, 1, manager.GetBulkCount())

	// Flush specific container
	manager.FlushContainer(containerID)

	// Give some time for flush to complete
	time.Sleep(100 * time.Millisecond)

	sendMutex.Lock()
	assert.Equal(t, 1, sendCount)
	assert.Equal(t, containerID, flushedContainerID)
	sendMutex.Unlock()

	assert.Equal(t, 0, manager.GetBulkCount())
}

func TestAlertBulkManager_FlushAll(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		return nil
	}

	manager := NewAlertBulkManager(50, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	// Add alerts for multiple containers
	for c := 0; c < 3; c++ {
		containerID := "container-" + string(rune('1'+c))
		for i := 0; i < 2; i++ {
			alert := createTestAlert(containerID, "test-alert")
			processTree := createTestProcessTree(uint32(100 + i))
			manager.AddAlert(alert, processTree, nil)
		}
	}

	assert.Equal(t, 3, manager.GetBulkCount())

	// Flush all
	manager.FlushAll()

	// Give some time for flush to complete
	time.Sleep(100 * time.Millisecond)

	sendMutex.Lock()
	assert.Equal(t, 3, sendCount, "Should have flushed all 3 containers")
	sendMutex.Unlock()

	assert.Equal(t, 0, manager.GetBulkCount())
}

func TestAlertBulkManager_EmptyContainerID(t *testing.T) {
	sendCount := 0
	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendCount++
		return nil
	}

	manager := NewAlertBulkManager(50, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	// Add alert with empty container ID
	alert := createTestAlert("", "test-alert")
	processTree := createTestProcessTree(100)
	manager.AddAlert(alert, processTree, nil)

	// Should not create a bulk
	assert.Equal(t, 0, manager.GetBulkCount())
	assert.Equal(t, 0, sendCount)
}

func TestAlertBulkManager_RaceConditionProtection(t *testing.T) {
	// This test verifies that concurrent AddAlert calls and background flush
	// don't cause double-flushing of the same bulk
	sendCount := 0
	var sendMutex sync.Mutex
	sentBulks := make(map[string]int) // containerID -> number of times flushed

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		sentBulks[containerID]++
		return nil
	}

	manager := NewAlertBulkManager(5, 1, 0, 0, 0, 0, sendFunc) // Small size and timeout, use defaults for queue params
	manager.Start()
	defer manager.Stop()

	containerID := "race-test-container"

	// Use WaitGroup to coordinate goroutines
	var wg sync.WaitGroup

	// Goroutine 1: Add alerts rapidly to trigger size-based flush
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			alert := createTestAlert(containerID, "test-alert")
			processTree := createTestProcessTree(uint32(100 + i))
			manager.AddAlert(alert, processTree, nil)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 2: Add alerts to a different bulk
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			alert := createTestAlert("container-2", "test-alert")
			processTree := createTestProcessTree(uint32(200 + i))
			manager.AddAlert(alert, processTree, nil)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for goroutines to complete
	wg.Wait()

	// Wait for background flush to potentially trigger
	time.Sleep(2 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Each container should have been flushed exactly once
	// Even though both size limit and timeout could have triggered
	assert.LessOrEqual(t, sentBulks[containerID], 1, "Container should be flushed at most once")
	assert.LessOrEqual(t, sentBulks["container-2"], 1, "Container-2 should be flushed at most once")

	// Total sends should equal number of unique containers that were flushed
	assert.Equal(t, len(sentBulks), sendCount, "Total sends should match unique containers flushed")
}

// ==================== SEND QUEUE TESTS ====================

func TestSendQueue_SuccessfulSendThroughQueue(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	receivedContainers := make([]string, 0)

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		receivedContainers = append(receivedContainers, containerID)
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	// Add alerts to trigger flush
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-1", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Wait for async processing
	time.Sleep(500 * time.Millisecond)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify send occurred
	assert.Equal(t, 1, sendCount, "Should have sent one bulk")
	assert.Contains(t, receivedContainers, "container-1")
}

func TestSendQueue_RetryOnFailure(t *testing.T) {
	sendAttempts := 0
	var sendMutex sync.Mutex
	failUntilAttempt := 2 // Fail first 2 attempts, succeed on 3rd

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendAttempts++
		if sendAttempts < failUntilAttempt {
			return assert.AnError // Simulate failure
		}
		return nil // Success
	}

	manager := NewAlertBulkManager(5, 10, 1000, 3, 100, 5000, sendFunc) // Fast retries for testing
	manager.Start()
	defer manager.Stop()

	// Add alerts to trigger flush
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-1", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Wait for retries to complete
	time.Sleep(2 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify retries occurred
	assert.GreaterOrEqual(t, sendAttempts, failUntilAttempt, "Should have retried until success")
}

func TestSendQueue_MaxRetriesExceeded(t *testing.T) {
	sendAttempts := 0
	var sendMutex sync.Mutex

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendAttempts++
		return assert.AnError // Always fail
	}

	manager := NewAlertBulkManager(5, 10, 1000, 3, 100, 5000, sendFunc) // Max 3 retries, fast delays
	manager.Start()
	defer manager.Stop()

	// Add alerts to trigger flush
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-1", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Wait for all retries to exhaust
	time.Sleep(3 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify gave up after max retries (1 initial + 3 retries = 4 total attempts)
	assert.Equal(t, 4, sendAttempts, "Should have attempted 1 initial + 3 retries")
}

func TestSendQueue_QueueFullHandling(t *testing.T) {
	var blockMutex sync.Mutex
	blockMutex.Lock() // Lock to block sending

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		blockMutex.Lock()
		defer blockMutex.Unlock()
		return nil
	}

	// Create manager with very small queue
	manager := NewAlertBulkManager(5, 10, 2, 0, 100, 5000, sendFunc) // Queue size of 2
	manager.Start()
	defer func() {
		blockMutex.Unlock() // Unblock to allow graceful shutdown
		manager.Stop()
	}()

	// Try to enqueue more items than queue can hold
	for i := 0; i < 10; i++ {
		for j := 0; j < 5; j++ {
			alert := createTestAlert("container-"+string(rune('1'+i)), "test-alert")
			processTree := createTestProcessTree(uint32(100 + j))
			manager.AddAlert(alert, processTree, nil)
		}
	}

	// Wait for enqueue attempts
	time.Sleep(2 * time.Second)

	// Queue should have been full, so some bulks were dropped (verified via logs)
}

func TestSendQueue_GracefulShutdownWithDrain(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex
	receivedContainers := make([]string, 0)

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		time.Sleep(50 * time.Millisecond) // Simulate slow send
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		receivedContainers = append(receivedContainers, containerID)
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()

	// Enqueue several bulks
	for i := 0; i < 3; i++ {
		for j := 0; j < 5; j++ {
			alert := createTestAlert("container-"+string(rune('1'+i)), "test-alert")
			processTree := createTestProcessTree(uint32(100 + j))
			manager.AddAlert(alert, processTree, nil)
		}
	}

	// Give a moment for enqueuing
	time.Sleep(100 * time.Millisecond)

	// Stop should drain the queue
	manager.Stop()

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// All bulks should have been sent
	assert.Equal(t, 3, sendCount, "All enqueued bulks should be sent during drain")
}

func TestSendQueue_ConcurrentEnqueueing(t *testing.T) {
	sendCount := 0
	var sendMutex sync.Mutex

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendCount++
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 0, 0, 0, 0, sendFunc) // Use defaults for queue params
	manager.Start()
	defer manager.Stop()

	// Multiple goroutines adding alerts concurrently
	var wg sync.WaitGroup
	numGoroutines := 10
	alertsPerGoroutine := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < alertsPerGoroutine; j++ {
				alert := createTestAlert("container-"+string(rune('A'+id)), "test-alert")
				processTree := createTestProcessTree(uint32(100 + j))
				manager.AddAlert(alert, processTree, nil)
			}
		}(i)
	}

	wg.Wait()

	// Wait for async processing
	time.Sleep(1 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify all bulks were sent
	assert.Equal(t, numGoroutines, sendCount, "Should have sent one bulk per container")
}

func TestSendQueue_ExponentialBackoff(t *testing.T) {
	sendAttempts := 0
	attemptTimes := make([]time.Time, 0)
	var sendMutex sync.Mutex

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		sendAttempts++
		attemptTimes = append(attemptTimes, time.Now())
		if sendAttempts < 4 {
			return assert.AnError // Fail first 3 attempts
		}
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 1000, 3, 200, 5000, sendFunc) // 200ms base delay
	manager.Start()
	defer manager.Stop()

	// Add alerts to trigger flush
	for i := 0; i < 5; i++ {
		alert := createTestAlert("container-1", "test-alert")
		processTree := createTestProcessTree(uint32(100 + i))
		manager.AddAlert(alert, processTree, nil)
	}

	// Wait for retries to complete
	time.Sleep(3 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify exponential backoff occurred
	assert.Equal(t, 4, sendAttempts, "Should have 1 initial + 3 retries")
	assert.GreaterOrEqual(t, len(attemptTimes), 4)

	// Check delays between attempts (allowing some tolerance)
	if len(attemptTimes) >= 4 {
		// First retry should be ~200ms after initial
		delay1 := attemptTimes[1].Sub(attemptTimes[0])
		assert.Greater(t, delay1, 150*time.Millisecond, "First retry delay should be ~200ms")
		assert.Less(t, delay1, 400*time.Millisecond)

		// Second retry should be ~400ms after first retry
		delay2 := attemptTimes[2].Sub(attemptTimes[1])
		assert.Greater(t, delay2, 300*time.Millisecond, "Second retry delay should be ~400ms")
		assert.Less(t, delay2, 600*time.Millisecond)
	}
}

func TestSendQueue_FIFOOrderingWithRetry(t *testing.T) {
	// This test verifies that FIFO ordering is maintained even when retries occur
	sendOrder := make([]string, 0)
	var sendMutex sync.Mutex
	failFirstBulk := true

	sendFunc := func(containerID string, alerts []apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()

		// Fail the first bulk on its first attempt only
		if containerID == "container-1" && failFirstBulk {
			failFirstBulk = false
			return assert.AnError
		}

		// Record successful send order
		sendOrder = append(sendOrder, containerID)
		return nil
	}

	manager := NewAlertBulkManager(5, 10, 1000, 3, 100, 5000, sendFunc) // Fast retry for testing
	manager.Start()
	defer manager.Stop()

	// Enqueue three bulks in order: container-1, container-2, container-3
	for i := 1; i <= 3; i++ {
		for j := 0; j < 5; j++ {
			alert := createTestAlert("container-"+string(rune('0'+i)), "test-alert")
			processTree := createTestProcessTree(uint32(100*i + j))
			manager.AddAlert(alert, processTree, nil)
		}
		time.Sleep(10 * time.Millisecond) // Small delay to ensure ordering
	}

	// Wait for all to process
	time.Sleep(2 * time.Second)

	sendMutex.Lock()
	defer sendMutex.Unlock()

	// Verify FIFO ordering is maintained despite container-1 retry
	// Expected: container-1 (retry succeeds), container-2, container-3
	assert.Equal(t, 3, len(sendOrder), "Should have sent 3 bulks")
	assert.Equal(t, "container-1", sendOrder[0], "container-1 should be sent first (after retry)")
	assert.Equal(t, "container-2", sendOrder[1], "container-2 should be sent second")
	assert.Equal(t, "container-3", sendOrder[2], "container-3 should be sent third")
}
