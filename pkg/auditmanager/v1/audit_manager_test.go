package v1

import (
	"context"
	"os"
	"testing"

	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditRuleParsing(t *testing.T) {
	tests := []struct {
		name         string
		rawRule      string
		expectError  bool
		expectedKey  string
		expectedType string
	}{
		{
			name:         "File watch rule",
			rawRule:      "-w /etc/passwd -p wa -k identity",
			expectError:  false,
			expectedKey:  "identity",
			expectedType: "file_watch",
		},
		{
			name:         "Syscall rule",
			rawRule:      "-a always,exit -F arch=b64 -S execve -k exec",
			expectError:  false,
			expectedKey:  "exec",
			expectedType: "syscall",
		},
		{
			name:        "Invalid rule",
			rawRule:     "invalid rule format",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := parseAuditRule(tt.rawRule)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, rule)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rule)
			assert.Equal(t, tt.expectedKey, rule.Key)
			assert.Equal(t, tt.expectedType, rule.RuleType)
			assert.Equal(t, tt.rawRule, rule.RawRule)
		})
	}
}

func TestHardcodedRulesLoading(t *testing.T) {
	rules, err := LoadHardcodedRules()
	require.NoError(t, err)
	assert.NotEmpty(t, rules)

	// Verify we have expected rules
	foundIdentityRule := false
	foundExecRule := false

	for _, rule := range rules {
		if rule.Key == "identity" && rule.RuleType == "file_watch" {
			foundIdentityRule = true
		}
		if rule.Key == "exec" && rule.RuleType == "syscall" {
			foundExecRule = true
		}
	}

	assert.True(t, foundIdentityRule, "Should have identity file watch rule")
	assert.True(t, foundExecRule, "Should have exec syscall rule")
}

func TestAuditEventCreation(t *testing.T) {
	event := NewAuditEvent(12345, "PATH")

	assert.Equal(t, uint64(12345), event.AuditID)
	assert.Equal(t, "PATH", event.MessageType)
	assert.True(t, event.Success) // Default value
	assert.NotZero(t, event.Timestamp)
}

func TestAuditMessageParsing(t *testing.T) {
	// Create a mock audit manager for testing parsing
	am := &AuditManagerV1{}

	tests := []struct {
		name         string
		rawMessage   string
		expectedType string
		expectedPath string
		expectedComm string
	}{
		{
			name:         "PATH message",
			rawMessage:   `type=PATH msg=audit(1234567890.123:12345): item=0 name="/etc/passwd" comm="cat"`,
			expectedType: "PATH",
			expectedPath: "/etc/passwd",
			expectedComm: "cat",
		},
		{
			name:         "SYSCALL message",
			rawMessage:   `type=SYSCALL msg=audit(1234567890.123:12345): arch=c000003e syscall=2 comm="cat" pid=1234`,
			expectedType: "SYSCALL",
			expectedComm: "cat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := am.parseAuditMessage([]byte(tt.rawMessage))
			require.NoError(t, err)
			require.NotNil(t, event)

			assert.Equal(t, tt.expectedType, event.MessageType)
			if tt.expectedPath != "" {
				assert.Equal(t, tt.expectedPath, event.Path)
			}
			if tt.expectedComm != "" {
				assert.Equal(t, tt.expectedComm, event.Comm)
			}
			assert.Equal(t, tt.rawMessage, event.RawMessage)
		})
	}
}

// TestAuditManagerCreation tests the basic creation of audit manager
func TestAuditManagerCreation(t *testing.T) {
	mockExporter := &exporters.ExporterBus{} // This will need to be a proper mock

	// This test will skip if we don't have privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping audit manager creation test - requires root privileges")
	}

	am, err := NewAuditManagerV1(mockExporter)
	if err != nil {
		// If we can't create due to audit subsystem being unavailable, skip
		t.Skipf("Skipping audit manager test - audit subsystem not available: %v", err)
	}

	require.NotNil(t, am)
	assert.True(t, am.enabled)
}

// TestAuditManagerMockMode tests that we can create audit manager in mock mode
func TestAuditManagerMockMode(t *testing.T) {
	mockManager := auditmanager.NewAuditManagerMock()
	require.NotNil(t, mockManager)

	// Test that mock methods don't panic
	ctx := context.Background()
	err := mockManager.Start(ctx)
	assert.NoError(t, err)

	err = mockManager.Stop()
	assert.NoError(t, err)
}
