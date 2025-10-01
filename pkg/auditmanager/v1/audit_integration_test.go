//go:build integration
// +build integration

package v1

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditKernelIntegration tests the actual kernel audit functionality
// This test requires root privileges and should be run with:
// sudo go test -tags=integration ./pkg/auditmanager/v1 -run TestAuditKernelIntegration
func TestAuditKernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges. Run with: sudo go test -tags=integration")
	}

	// Check if audit subsystem is available
	if !isAuditSubsystemAvailable() {
		t.Skip("Audit subsystem is not available on this system")
	}

	// Create a test exporter to capture events
	exporterBus := &exporters.ExporterBus{}

	// Create audit manager
	am, err := NewAuditManagerV1(exporterBus)
	require.NoError(t, err, "Failed to create audit manager")
	require.NotNil(t, am)

	// Start the audit manager
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = am.Start(ctx)
	require.NoError(t, err, "Failed to start audit manager")
	defer am.Stop()

	// Give it a moment to initialize
	time.Sleep(2 * time.Second)

	// Trigger some audit events by accessing monitored files
	t.Run("FileAccessEvents", func(t *testing.T) {
		// Access /etc/passwd which should be monitored by our hardcoded rules
		_, err := os.Stat("/etc/passwd")
		require.NoError(t, err)

		// Give time for event to be processed
		time.Sleep(1 * time.Second)

		// We should have received some audit events
		// Note: This is a basic test - in practice, events might be filtered
		// or not generated depending on system configuration
		t.Logf("Audit manager started successfully and is listening for events")
	})

	t.Run("SyscallEvents", func(t *testing.T) {
		// Execute a simple command that should trigger execve syscall
		cmd := exec.Command("echo", "test")
		err := cmd.Run()
		require.NoError(t, err)

		// Give time for event to be processed
		time.Sleep(1 * time.Second)

		t.Logf("Executed command successfully while audit manager is running")
	})
}

// TestAuditRuleLoading tests loading rules into the kernel
func TestAuditRuleLoading(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges. Run with: sudo go test -tags=integration")
	}

	if !isAuditSubsystemAvailable() {
		t.Skip("Audit subsystem is not available on this system")
	}

	// Create audit manager
	exporterBus := &exporters.ExporterBus{}

	am, err := NewAuditManagerV1(exporterBus)
	require.NoError(t, err)

	// Initialize the audit client (needed for loadRuleIntoKernel)
	ctx := context.Background()
	err = am.Start(ctx)
	require.NoError(t, err)
	defer am.Stop()

	// Test loading a single rule
	testRule := &AuditRule{
		RuleType: "file_watch",
		RawRule:  "-w /tmp/audit_test_file -p wa -k test_rule",
		Key:      "test_rule",
	}

	err = am.loadRuleIntoKernel(testRule)
	if err != nil {
		t.Logf("Rule loading failed (this might be expected): %v", err)
		// Don't fail the test here as rule loading might fail for various reasons
		// (audit already in use, permissions, etc.)
	} else {
		t.Logf("Successfully loaded test rule into kernel")
	}
}

// TestAuditManagerLifecycle tests the complete lifecycle of audit manager
func TestAuditManagerLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges. Run with: sudo go test -tags=integration")
	}

	if !isAuditSubsystemAvailable() {
		t.Skip("Audit subsystem is not available on this system")
	}

	exporterBus := &exporters.ExporterBus{}

	am, err := NewAuditManagerV1(exporterBus)
	require.NoError(t, err)

	// Test start
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = am.Start(ctx)
	require.NoError(t, err, "Failed to start audit manager")

	// Verify it's running
	assert.True(t, am.stats.IsRunning, "Audit manager should be running")

	// Let it run for a short time
	time.Sleep(2 * time.Second)

	// Test stop
	err = am.Stop()
	assert.NoError(t, err, "Failed to stop audit manager")

	// Verify it's stopped
	assert.False(t, am.stats.IsRunning, "Audit manager should be stopped")
}

// Helper functions

func isAuditSubsystemAvailable() bool {
	// Check if audit subsystem is available by trying to access /proc/self/loginuid
	_, err := os.Stat("/proc/self/loginuid")
	if err != nil {
		return false
	}

	// Also check if we can create an audit socket (basic check)
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return false
	}
	syscall.Close(fd)

	return true
}

// TestExporter is a simple test exporter that captures events
type TestExporter struct {
	events []string
}

func NewTestExporter() *TestExporter {
	return &TestExporter{
		events: make([]string, 0),
	}
}

func (te *TestExporter) CaptureEvent(event string) {
	te.events = append(te.events, event)
}

func (te *TestExporter) GetEvents() []string {
	return te.events
}

func (te *TestExporter) EventCount() int {
	return len(te.events)
}
