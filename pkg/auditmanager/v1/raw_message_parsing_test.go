package v1

import (
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRawAuditMessageParsing tests parsing of raw audit messages and captures the resulting events
func TestRawAuditMessageParsing(t *testing.T) {
	// Create a mock exporter to capture events
	capturedEvents := make([]auditmanager.AuditResult, 0)
	mockExporter := &MockExporter{
		SendAuditAlertFunc: func(auditResult auditmanager.AuditResult) {
			capturedEvents = append(capturedEvents, auditResult)
		},
	}

	// Create audit manager with mock exporter
	// Create a custom ExporterBus with our mock exporter
	exporterBus := exporters.NewExporterBus(([]exporters.Exporter{mockExporter}))

	// Use the existing mock from processtree package
	mockProcessTreeManager := &processtree.ProcessTreeManagerMock{}

	am, err := NewAuditManagerV1(&config.Config{}, exporterBus, mockProcessTreeManager)
	require.NoError(t, err)
	require.NotNil(t, am)

	// Test cases with different raw audit messages
	testCases := []struct {
		name            string
		rawMessage      string
		expectedSuccess bool
		expectedSyscall string
		expectedKeys    []string
		expectedAUID    uint32
		expectedEUID    uint32
		expectedExit    int32
	}{
		{
			name:            "Successful sethostname syscall",
			rawMessage:      "audit(1759225399.402:2608888): arch=c000003e syscall=170 success=yes exit=0 a0=560387cbd2a0 a1=14 a2=14 a3=fffffffffffff000 items=0 ppid=280777 pid=280786 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4294967295 comm=\"hostname\" exe=\"/usr/bin/hostname\" subj=unconfined key=\"hostname-changes\"",
			expectedSuccess: true,
			expectedSyscall: "sethostname",
			expectedKeys:    []string{"hostname-changes"},
			expectedAUID:    0,
			expectedEUID:    0,
			expectedExit:    0,
		},
		{
			name:            "Failed sethostname syscall",
			rawMessage:      "audit(1759226300.525:2609261): arch=c000003e syscall=170 success=no exit=-1 a0=56261c2622a0 a1=14 a2=14 a3=fffffffffffff000 items=0 ppid=281500 pid=281527 auid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=4294967295 comm=\"hostname\" exe=\"/usr/bin/hostname\" subj=unconfined key=\"hostname-changes\"",
			expectedSuccess: false,
			expectedSyscall: "sethostname",
			expectedKeys:    []string{"hostname-changes"},
			expectedAUID:    1000,
			expectedEUID:    1000,
			expectedExit:    -1,
		},
		{
			name:            "File access event",
			rawMessage:      "audit(1759226300.525:2609262): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff12345678 a2=0 items=1 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=12345 comm=\"cat\" exe=\"/bin/cat\" subj=unconfined key=\"file-access\"",
			expectedSuccess: true,
			expectedSyscall: "openat",
			expectedKeys:    []string{"file-access"},
			expectedAUID:    1000,
			expectedEUID:    1000,
			expectedExit:    3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear captured events
			capturedEvents = capturedEvents[:0]

			// Parse the raw message - need to specify message type
			msg, err := auparse.Parse(auparse.AUDIT_SYSCALL, tc.rawMessage)
			require.NoError(t, err, "Failed to parse raw audit message")

			// Use the audit manager's parsing method to create the event
			event := am.parseAggregatedAuditMessages([]*auparse.AuditMessage{msg})
			require.NotNil(t, event, "Failed to parse audit message into event")

			// Process the event through the audit manager
			am.processAuditEvent(event)

			// Verify we captured an event
			require.Len(t, capturedEvents, 1, "Should have captured exactly one event")

			// Get the captured event
			event = capturedEvents[0].GetAuditEvent()

			// Verify the parsed fields
			assert.Equal(t, tc.expectedSuccess, event.Success, "Success field should match")
			assert.Equal(t, tc.expectedSyscall, event.Syscall, "Syscall field should match")
			assert.Equal(t, tc.expectedKeys, event.Keys, "Keys should match")
			assert.Equal(t, tc.expectedAUID, event.AUID, "AUID should match")
			assert.Equal(t, tc.expectedEUID, event.EUID, "EUID should match")
			assert.Equal(t, tc.expectedExit, event.Exit, "Exit code should match")

			// Verify the raw message is preserved
			assert.Equal(t, tc.rawMessage, event.RawMessage, "Raw message should be preserved")

			// Verify timestamp is set
			assert.NotZero(t, event.Timestamp, "Timestamp should be set")

			// Verify audit ID is set
			assert.NotZero(t, event.AuditID, "Audit ID should be set")

			// Print the parsed event for debugging
			t.Logf("Parsed event: Success=%v, Syscall=%s, UID=%d, EUID=%d, Exit=%d, Keys=%v",
				event.Success, event.Syscall, event.AUID, event.EUID, event.Exit, event.Keys)

			// Print the raw data for debugging
			t.Logf("Raw data: %+v", event.Data)
		})
	}
}

// MockExporter is a mock implementation of the Exporter interface for testing
type MockExporter struct {
	SendAuditAlertFunc   func(auditmanager.AuditResult)
	SendMalwareAlertFunc func(malwaremanager.MalwareResult)
	SendRuleAlertFunc    func(ruleengine.RuleFailure)
}

func (m *MockExporter) SendFimAlerts(fimEvents []hostfimsensor.FimEvent) {
	//TODO implement me
	panic("implement me")
}

func (m *MockExporter) SendAuditAlert(auditResult auditmanager.AuditResult) {
	if m.SendAuditAlertFunc != nil {
		m.SendAuditAlertFunc(auditResult)
	}
}

func (m *MockExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	if m.SendMalwareAlertFunc != nil {
		m.SendMalwareAlertFunc(malwareResult)
	}
}

func (m *MockExporter) SendRuleAlert(ruleFailure ruleengine.RuleFailure) {
	if m.SendRuleAlertFunc != nil {
		m.SendRuleAlertFunc(ruleFailure)
	}
}
