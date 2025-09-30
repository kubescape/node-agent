package exporters

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/auditmanager"
)

func TestAuditbeatExporter_ConvertToAuditbeatEvent(t *testing.T) {
	// Create a sample audit event
	auditEvent := &auditmanager.AuditEvent{
		AuditID:   12345,
		Timestamp: types.Time(time.Now().UnixNano()),
		Sequence:  100,
		Type:      auparse.AUDIT_SYSCALL,
		PID:       1234,
		PPID:      567,
		AUID:      1000,
		UID:       1000,
		GID:       1000,
		EUID:      1000,
		EGID:      1000,
		Comm:      "bash",
		Exe:       "/bin/bash",
		CWD:       "/home/user",
		Args:      []string{"bash", "-c", "ls -la"},
		Syscall:   "execve",
		Success:   true,
		Exit:      0,
		Path:      "/bin/ls",
		Mode:      0755,
		Inode:     123456,
		DevMajor:  8,
		DevMinor:  1,
		Keys:      []string{"test-key"},
		RuleType:  "syscall",
		Pod:       "test-pod",
		Namespace: "default",
		Data: map[string]string{
			"syscall": "execve",
			"exit":    "0",
			"a0":      "0x7fff12345678",
			"a1":      "0x7fff12345680",
		},
	}

	// Create audit result
	auditResult := auditmanager.NewAuditResult(auditEvent)

	// Create exporter config
	config := AuditbeatExporterConfig{
		URL:                "http://localhost:8080",
		TimeoutSeconds:     5,
		MaxEventsPerMinute: 1000,
		BatchSize:          10,
		EnableBatching:     false,
	}

	// Create exporter
	exporter, err := NewAuditbeatExporter(config, "test-cluster", "test-node", nil)
	if err != nil {
		t.Fatalf("Failed to create auditbeat exporter: %v", err)
	}

	// Convert to auditbeat event
	auditbeatEvent := exporter.convertToAuditbeatEvent(auditResult)

	// Verify basic structure
	if auditbeatEvent.timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Verify event info
	eventFields, exists := auditbeatEvent.rootFields["event"]
	if !exists {
		t.Fatal("Event fields should exist")
	}

	eventMap, ok := eventFields.(map[string]interface{})
	if !ok {
		t.Fatal("Event fields should be map[string]interface{}")
	}

	_, exists = eventMap["category"]
	if !exists {
		t.Error("Event category should exist")
	}

	_, exists = eventMap["action"]
	if !exists {
		t.Error("Event action should exist")
	}

	_, exists = eventMap["outcome"]
	if !exists {
		t.Error("Event outcome should exist")
	}

	dataset, exists := eventMap["dataset"]
	if !exists || dataset != "auditd.auditd" {
		t.Errorf("Expected dataset 'auditd.auditd', got %v", dataset)
	}

	// Verify auditd info
	_, exists = auditbeatEvent.moduleFields["message_type"]
	if !exists {
		t.Error("Auditd message type should exist")
	}

	sequence, exists := auditbeatEvent.moduleFields["sequence"]
	if !exists || sequence != auditEvent.Sequence {
		t.Errorf("Expected sequence %d, got %v", auditEvent.Sequence, sequence)
	}

	_, exists = auditbeatEvent.moduleFields["data"]
	if !exists {
		t.Error("Auditd data should exist")
	}

	// Verify process info
	process, exists := auditbeatEvent.rootFields["process"]
	if !exists {
		t.Error("Process info should exist")
	} else {
		processMap, ok := process.(map[string]interface{})
		if !ok {
			t.Fatal("Process should be map[string]interface{}")
		}

		pid, exists := processMap["pid"]
		if !exists || pid != int(auditEvent.PID) {
			t.Errorf("Expected PID %d, got %v", auditEvent.PID, pid)
		}

		name, exists := processMap["name"]
		if !exists || name != auditEvent.Comm {
			t.Errorf("Expected process name %s, got %v", auditEvent.Comm, name)
		}

		executable, exists := processMap["executable"]
		if !exists || executable != auditEvent.Exe {
			t.Errorf("Expected executable %s, got %v", auditEvent.Exe, executable)
		}

		args, exists := processMap["args"]
		if !exists {
			t.Error("Process args should exist")
		}
		_ = args // Use args to avoid unused variable warning
	}

	// Verify user info
	user, exists := auditbeatEvent.rootFields["user"]
	if !exists {
		t.Error("User info should exist")
	} else {
		userMap, ok := user.(map[string]interface{})
		if !ok {
			t.Fatal("User should be map[string]interface{}")
		}

		id, exists := userMap["id"]
		if !exists || id != "1000" {
			t.Errorf("Expected user ID '1000', got %v", id)
		}
	}

	// Verify file info
	file, exists := auditbeatEvent.rootFields["file"]
	if !exists {
		t.Error("File info should exist for file operations")
	} else {
		fileMap, ok := file.(map[string]interface{})
		if !ok {
			t.Fatal("File should be map[string]interface{}")
		}

		path, exists := fileMap["path"]
		if !exists || path != auditEvent.Path {
			t.Errorf("Expected file path %s, got %v", auditEvent.Path, path)
		}

		mode, exists := fileMap["mode"]
		if !exists || mode != "0755" {
			t.Errorf("Expected file mode '0755', got %v", mode)
		}
	}

	// Verify Kubernetes info
	k8s, exists := auditbeatEvent.rootFields["kubernetes"]
	if !exists {
		t.Error("Kubernetes info should exist")
	} else {
		k8sMap, ok := k8s.(map[string]interface{})
		if !ok {
			t.Fatal("Kubernetes should be map[string]interface{}")
		}

		podName, exists := k8sMap["pod.name"]
		if !exists || podName != auditEvent.Pod {
			t.Errorf("Expected pod name %s, got %v", auditEvent.Pod, podName)
		}

		namespace, exists := k8sMap["namespace.name"]
		if !exists || namespace != auditEvent.Namespace {
			t.Errorf("Expected namespace %s, got %v", auditEvent.Namespace, namespace)
		}
	}

	// Verify service info
	service, exists := auditbeatEvent.rootFields["service.type"]
	if !exists || service != "auditd" {
		t.Errorf("Expected service type 'auditd', got %v", service)
	}

	// Verify host info
	hostName, exists := auditbeatEvent.rootFields["host.name"]
	if !exists || hostName != "test-node" {
		t.Errorf("Expected host name 'test-node', got %v", hostName)
	}

	// Verify agent info
	agent, exists := auditbeatEvent.rootFields["agent"]
	if !exists {
		t.Error("Agent info should exist")
	} else {
		agentMap, ok := agent.(map[string]interface{})
		if !ok {
			t.Fatal("Agent should be map[string]interface{}")
		}

		agentType, exists := agentMap["type"]
		if !exists || agentType != "kubescape-node-agent" {
			t.Errorf("Expected agent type 'kubescape-node-agent', got %v", agentType)
		}
	}
}

func TestAuditbeatExporter_EventCategorization(t *testing.T) {
	config := AuditbeatExporterConfig{
		URL:                "http://localhost:8080",
		TimeoutSeconds:     5,
		MaxEventsPerMinute: 1000,
		BatchSize:          10,
		EnableBatching:     false,
	}

	exporter, err := NewAuditbeatExporter(config, "test-cluster", "test-node", nil)
	if err != nil {
		t.Fatalf("Failed to create auditbeat exporter: %v", err)
	}

	tests := []struct {
		name             string
		auditEvent       *auditmanager.AuditEvent
		expectedCategory string
		expectedAction   string
		expectedType     string
	}{
		{
			name: "syscall event",
			auditEvent: &auditmanager.AuditEvent{
				Syscall: "execve",
				Success: true,
			},
			expectedCategory: "process",
			expectedAction:   "executed",
			expectedType:     "start",
		},
		{
			name: "file read event",
			auditEvent: &auditmanager.AuditEvent{
				Path:      "/etc/passwd",
				Operation: "read",
				Success:   true,
			},
			expectedCategory: "file",
			expectedAction:   "accessed",
			expectedType:     "change",
		},
		{
			name: "file write event",
			auditEvent: &auditmanager.AuditEvent{
				Path:      "/tmp/test.txt",
				Operation: "write",
				Success:   true,
			},
			expectedCategory: "file",
			expectedAction:   "modified",
			expectedType:     "change",
		},
		{
			name: "network event",
			auditEvent: &auditmanager.AuditEvent{
				SockFamily: "inet",
				Success:    true,
			},
			expectedCategory: "network",
			expectedAction:   "connected",
			expectedType:     "info",
		},
		{
			name: "system event",
			auditEvent: &auditmanager.AuditEvent{
				Success: true,
			},
			expectedCategory: "system",
			expectedAction:   "executed",
			expectedType:     "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditResult := auditmanager.NewAuditResult(tt.auditEvent)
			auditbeatEvent := exporter.convertToAuditbeatEvent(auditResult)

			eventFields, exists := auditbeatEvent.rootFields["event"]
			if !exists {
				t.Fatal("Event fields should exist")
			}

			eventMap, ok := eventFields.(map[string]interface{})
			if !ok {
				t.Fatal("Event fields should be map[string]interface{}")
			}

			category, exists := eventMap["category"]
			if !exists {
				t.Error("Event category should exist")
			} else if category != tt.expectedCategory {
				t.Errorf("Expected category %s, got %v", tt.expectedCategory, category)
			}

			action, exists := eventMap["action"]
			if !exists {
				t.Error("Event action should exist")
			} else if action != tt.expectedAction {
				t.Errorf("Expected action %s, got %v", tt.expectedAction, action)
			}

			eventType, exists := eventMap["type"]
			if !exists {
				t.Error("Event type should exist")
			} else {
				typeSlice, ok := eventType.([]string)
				if !ok {
					t.Fatal("Event type should be []string")
				}
				if len(typeSlice) == 0 {
					t.Error("Event type should not be empty")
				} else if typeSlice[0] != tt.expectedType {
					t.Errorf("Expected type %s, got %s", tt.expectedType, typeSlice[0])
				}
			}
		})
	}
}

func TestAuditbeatExporter_JSONSerialization(t *testing.T) {
	// Create a sample audit event
	auditEvent := &auditmanager.AuditEvent{
		AuditID:   12345,
		Timestamp: types.Time(time.Now().UnixNano()),
		Sequence:  100,
		Type:      auparse.AUDIT_SYSCALL,
		PID:       1234,
		PPID:      567,
		AUID:      1000,
		UID:       1000,
		GID:       1000,
		Comm:      "bash",
		Exe:       "/bin/bash",
		Syscall:   "execve",
		Success:   true,
		Exit:      0,
		Keys:      []string{"test-key"},
		RuleType:  "syscall",
		Data: map[string]string{
			"syscall": "execve",
			"exit":    "0",
		},
	}

	auditResult := auditmanager.NewAuditResult(auditEvent)

	config := AuditbeatExporterConfig{
		URL:                "http://localhost:8080",
		TimeoutSeconds:     5,
		MaxEventsPerMinute: 1000,
		BatchSize:          10,
		EnableBatching:     false,
	}

	exporter, err := NewAuditbeatExporter(config, "test-cluster", "test-node", nil)
	if err != nil {
		t.Fatalf("Failed to create auditbeat exporter: %v", err)
	}

	auditbeatEvent := exporter.convertToAuditbeatEvent(auditResult)

	// Test JSON serialization using direct method call
	jsonData, err := auditbeatEvent.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal auditbeat event to JSON: %v", err)
	}

	// Verify JSON contains expected fields
	jsonStr := string(jsonData)
	expectedFields := []string{
		"@timestamp",
		"event",
		"auditd",
		"service",
		"process",
		"user",
		"host",
		"agent",
	}

	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON should contain field: %s", field)
		}
	}

	// Test batch serialization
	events := []AuditbeatEvent{auditbeatEvent}
	batchData, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("Failed to marshal auditbeat event batch to JSON: %v", err)
	}

	// Verify it's an array
	if !contains(string(batchData), "[") || !contains(string(batchData), "]") {
		t.Error("Batch JSON should be an array")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
