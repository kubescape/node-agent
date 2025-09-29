package v1

import (
	"context"
	"os"
	"testing"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/config"
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

// Note: Removed TestAuditEventCreation - NewAuditEvent function no longer exists

// Note: Removed TestAuditMessageParsing - parseAuditMessage function no longer exists

// TestAuditManagerCreation tests the basic creation of audit manager
func TestAuditManagerCreation(t *testing.T) {
	mockExporter := &exporters.ExporterBus{} // This will need to be a proper mock

	// This test will skip if we don't have privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping audit manager creation test - requires root privileges")
	}

	// Create a minimal config for testing
	testConfig := &config.Config{}
	testConfig.AuditDetection.EventFilter.IncludeTypes = []auparse.AuditMessageType{auparse.AUDIT_SYSCALL, auparse.AUDIT_PATH}

	am, err := NewAuditManagerV1(testConfig, mockExporter)
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
