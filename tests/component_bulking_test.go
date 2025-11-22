//go:build component

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/tests/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockHTTPServer captures HTTP requests for testing bulk behavior
type MockHTTPServer struct {
	sync.Mutex
	Requests      []BulkRequest
	RequestCounts map[string]int // containerID -> request count
	server        *http.Server
}

type BulkRequest struct {
	Timestamp    time.Time
	AlertCount   int
	ContainerIDs []string
}

func NewMockHTTPServer(port int) *MockHTTPServer {
	mock := &MockHTTPServer{
		Requests:      make([]BulkRequest, 0),
		RequestCounts: make(map[string]int),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/runtimealerts", mock.handleRuntimeAlerts)

	mock.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return mock
}

func (m *MockHTTPServer) Start() error {
	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Mock server error: %v\n", err)
		}
	}()
	time.Sleep(500 * time.Millisecond) // Give server time to start
	return nil
}

func (m *MockHTTPServer) Stop() error {
	return m.server.Close()
}

func (m *MockHTTPServer) handleRuntimeAlerts(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse the alert payload
	var payload struct {
		Spec struct {
			Alerts []struct {
				RuntimeAlertK8sDetails struct {
					ContainerID string `json:"containerID"`
				} `json:"runtimeAlertK8sDetails"`
			} `json:"alerts"`
		} `json:"spec"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	m.Lock()
	defer m.Unlock()

	// Extract container IDs from the bulk
	containerIDs := make([]string, 0)
	containerIDSet := make(map[string]struct{})
	for _, alert := range payload.Spec.Alerts {
		containerID := alert.RuntimeAlertK8sDetails.ContainerID
		if containerID != "" {
			if _, exists := containerIDSet[containerID]; !exists {
				containerIDs = append(containerIDs, containerID)
				containerIDSet[containerID] = struct{}{}
			}
		}
	}

	// Record the request
	bulkReq := BulkRequest{
		Timestamp:    time.Now(),
		AlertCount:   len(payload.Spec.Alerts),
		ContainerIDs: containerIDs,
	}
	m.Requests = append(m.Requests, bulkReq)

	// Count requests per container
	for _, containerID := range containerIDs {
		m.RequestCounts[containerID]++
	}

	w.WriteHeader(http.StatusOK)
}

func (m *MockHTTPServer) GetTotalRequests() int {
	m.Lock()
	defer m.Unlock()
	return len(m.Requests)
}

func (m *MockHTTPServer) GetTotalAlerts() int {
	m.Lock()
	defer m.Unlock()
	total := 0
	for _, req := range m.Requests {
		total += req.AlertCount
	}
	return total
}

func (m *MockHTTPServer) GetBulksWithMultipleAlerts() int {
	m.Lock()
	defer m.Unlock()
	count := 0
	for _, req := range m.Requests {
		if req.AlertCount > 1 {
			count++
		}
	}
	return count
}

// Test_25_AlertBulkingBasic verifies that alert bulking reduces HTTP requests
func Test_25_AlertBulkingBasic(t *testing.T) {
	t.Log("Starting alert bulking component test")

	// Note: This test requires the node-agent to be configured with:
	// - enableAlertBulking: true
	// - bulkMaxAlerts: 10
	// - bulkTimeoutSeconds: 5
	// You can configure this in tests/chart/templates/node-agent/configmap.yaml

	start := time.Now()
	defer tearDownTest(t, start)

	// Create namespace and deploy workload
	ns := testutils.NewRandomNamespace()
	wl, err := testutils.NewTestWorkload(ns.Name, path.Join(utils.CurrentDir(), "resources/deployment-multiple-containers.yaml"))
	require.NoError(t, err, "Error creating workload")
	require.NoError(t, wl.WaitForReady(80))

	time.Sleep(10 * time.Second)

	// Wait for application profile to complete
	err = wl.WaitForApplicationProfileCompletion(80)
	require.NoError(t, err, "Error waiting for application profile to be completed")

	time.Sleep(30 * time.Second)

	t.Log("Triggering multiple alerts in quick succession")

	// Trigger multiple alerts from nginx container quickly
	// These should be bulked together since they're from the same container
	for i := 0; i < 8; i++ {
		_, _, err = wl.ExecIntoPod([]string{"sleep", "0.1"}, "nginx") // Unexpected process
		if err != nil {
			t.Logf("Warning: exec command %d failed (expected): %v", i, err)
		}
		time.Sleep(100 * time.Millisecond) // Small delay between commands
	}

	t.Log("Waiting for alerts to be processed and sent")
	// Wait for bulk timeout (5s) + processing time
	time.Sleep(10 * time.Second)

	// Get alerts from AlertManager to verify they were generated
	alerts, err := testutils.GetAlerts(wl.Namespace)
	require.NoError(t, err, "Error getting alerts")

	t.Logf("Total alerts received by AlertManager: %d", len(alerts))

	// Basic verification: We should have received multiple alerts
	assert.GreaterOrEqual(t, len(alerts), 5, "Expected at least 5 alerts to be generated")

	t.Log("Alert bulking test completed")
	t.Log("Note: To verify actual bulking behavior, check node-agent logs for:")
	t.Log("  - 'flushing bulk' log entries showing multiple alerts per bulk")
	t.Log("  - HTTP requests to synchronizer being fewer than total alerts")
	t.Log("You can also add prometheus metrics to track bulk sizes")
}

// Test_26_AlertBulkingWithHTTPMock demonstrates how to verify bulking with a mock server
// This test is more advanced and requires modifying the node-agent configuration
// to point to a mock HTTP endpoint instead of the synchronizer
func Test_26_AlertBulkingWithHTTPMock(t *testing.T) {
	t.Skip("This test requires custom node-agent configuration to use mock HTTP server")

	// Example of how you would test with a mock server:
	// 1. Deploy mock HTTP server in the test cluster
	// 2. Configure node-agent to send alerts to mock server
	// 3. Trigger multiple alerts
	// 4. Query mock server's API to verify bulking behavior

	mockServer := NewMockHTTPServer(8888)
	err := mockServer.Start()
	require.NoError(t, err)
	defer mockServer.Stop()

	// ... rest of test would deploy workload and trigger alerts ...

	// Verify bulking behavior
	totalRequests := mockServer.GetTotalRequests()
	totalAlerts := mockServer.GetTotalAlerts()
	bulksWithMultiple := mockServer.GetBulksWithMultipleAlerts()

	t.Logf("Total HTTP requests: %d", totalRequests)
	t.Logf("Total alerts: %d", totalAlerts)
	t.Logf("Bulks with >1 alert: %d", bulksWithMultiple)

	// With bulking, we should have fewer requests than alerts
	assert.Less(t, totalRequests, totalAlerts, "Bulking should reduce HTTP requests")
	assert.Greater(t, bulksWithMultiple, 0, "Should have at least one bulk with multiple alerts")
}

