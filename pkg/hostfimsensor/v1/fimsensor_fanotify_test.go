//go:build linux
// +build linux

package hostfimsensor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/auditmanager"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockExporter implements exporters.Exporter for testing
type MockExporter struct {
	events []fimtypes.FimEvent
}

func (m *MockExporter) SendAuditAlert(auditResult auditmanager.AuditResult) {
	//TODO implement me
	panic("implement me")
}

func (m *MockExporter) SendFimAlerts(events []fimtypes.FimEvent) {
	m.events = append(m.events, events...)
}

func (m *MockExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
}

func (m *MockExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
}

func TestNewHostFimSensorFanotify(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fim-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a mock exporter
	mockExporter := &MockExporter{}

	// Create path configurations
	pathConfigs := []HostFimPathConfig{
		{
			Path:     ".",
			OnCreate: true,
			OnChange: true,
			OnRemove: true,
		},
	}

	// Create the fanotify sensor
	sensor := NewHostFimSensorFanotify(tempDir, pathConfigs, mockExporter)
	require.NotNil(t, sensor)

	// Test that the sensor can be started
	err = sensor.Start()
	if err != nil {
		// If fanotify fails (e.g., no CAP_SYS_ADMIN), that's expected
		t.Logf("Fanotify failed as expected: %v", err)
		return
	}

	// Create a test file to trigger an event
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Wait a bit for the event to be processed
	time.Sleep(100 * time.Millisecond)

	// Stop the sensor
	sensor.Stop()
}

func TestFanotifyEventTypeConversion(t *testing.T) {
	sensor := &HostFimSensorFanotify{}

	// Test event type conversion
	config := HostFimPathConfig{
		OnCreate: true,
		OnChange: true,
		OnRemove: true,
		OnRename: true,
		OnChmod:  true,
		OnMove:   true,
	}

	eventTypes := sensor.getFanotifyEventTypes(config)
	assert.NotZero(t, eventTypes, "Event types should not be zero")
}
