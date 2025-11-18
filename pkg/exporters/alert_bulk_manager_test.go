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
	assert.Equal(t, uint32(100), bulk.mergedProcessTree.PID)
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
	assert.Equal(t, uint32(0), bulk.mergedProcessTree.PID)
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

	manager := NewAlertBulkManager(50, 10, sendFunc)
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

	manager := NewAlertBulkManager(5, 10, sendFunc)
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

	manager := NewAlertBulkManager(50, 2, sendFunc) // 2 second timeout
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

	manager := NewAlertBulkManager(5, 10, sendFunc)
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

	manager := NewAlertBulkManager(50, 10, sendFunc)
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

	manager := NewAlertBulkManager(50, 10, sendFunc)
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

	manager := NewAlertBulkManager(50, 10, sendFunc)
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

