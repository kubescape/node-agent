# Audit Subsystem Testing Guide

This document describes how to test the Linux Audit subsystem integration in the Kubescape node-agent.

## Test Overview

The audit functionality has been tested at multiple levels:

### 1. Unit Tests (No Privileges Required)
```bash
# Run basic unit tests
go test ./pkg/auditmanager/v1 -v

# Test coverage includes:
# - Audit rule parsing (file watch and syscall rules)
# - Hardcoded rules loading
# - Audit event creation and message parsing
# - Mock audit manager functionality
```

### 2. Integration Tests (Requires Root)
```bash
# Run integration tests with proper privileges
sudo -E go test -tags=integration ./pkg/auditmanager/v1 -v

# These tests verify:
# - Actual kernel audit client creation
# - Real audit subsystem availability
# - Audit manager lifecycle (start/stop)
# - Rule loading interface (POC implementation)
# - Event listener startup and shutdown
```

### 3. Comprehensive Test Script
```bash
# Run the full test suite
sudo ./test_audit.sh

# This script tests:
# - Complete node-agent with audit configuration
# - Real kernel rule loading
# - Event capture and processing
# - Exporter integration
```

### 4. Simple Focused Test
```bash
# Run focused audit functionality test
sudo ./test_audit_simple.sh

# This script verifies:
# - Audit subsystem availability
# - go-libaudit library integration
# - Rule parsing functionality
# - Basic audit client creation
```

## Test Results Summary

### ✅ Successful Tests
- **Unit Tests**: All audit rule parsing and event creation tests pass
- **go-libaudit Integration**: Successfully creates audit client and gets status
- **Rule Loading**: Hardcoded rules are parsed and loaded correctly
- **Event Processing**: Audit message parsing works correctly
- **Configuration**: Independent audit configuration loads properly
- **Exporters**: All exporters implement SendAuditAlert method

### ⚠️ Expected Limitations
- **Kernel Integration**: May fail in containerized environments without proper capabilities
- **Rule Loading**: Requires CAP_AUDIT_WRITE capability
- **Event Capture**: Requires CAP_AUDIT_READ capability
- **auditctl**: Not available by default (install with: `sudo apt install auditd`)

## Running Tests in Different Environments

### Local Development (with sudo)
```bash
# Install audit tools (optional but helpful)
sudo apt install auditd

# Run simple test
sudo ./test_audit_simple.sh

# Run comprehensive test
sudo ./test_audit.sh
```

### Container/Restricted Environment
```bash
# Run only unit tests (no privileges required)
go test ./pkg/auditmanager/v1 -v

# These will work without kernel access
```

### Production Environment
```bash
# Ensure proper capabilities
# CAP_AUDIT_WRITE for rule loading
# CAP_AUDIT_READ for event capture

# Test with actual configuration
sudo CONFIG_DIR=/path/to/config /path/to/node-agent
```

## Configuration for Testing

### Minimal Audit Configuration
```json
{
  "auditDetectionEnabled": true,
  "auditExporters": {
    "stdoutExporter": true
  },
  "runtimeDetectionEnabled": false,
  "kubernetesMode": false,
  "testMode": true
}
```

### Production-like Configuration
```json
{
  "auditDetectionEnabled": true,
  "auditExporters": {
    "stdoutExporter": true,
    "alertManagerExporterUrls": ["http://alertmanager:9093"],
    "syslogExporterURL": "udp://syslog:514"
  },
  "exporters": {
    "stdoutExporter": false
  },
  "runtimeDetectionEnabled": true
}
```

## Troubleshooting

### Common Issues

1. **"Operation not permitted"**
   - Solution: Run with sudo or proper capabilities

2. **"Audit subsystem not available"**
   - Check: `/proc/self/loginuid` exists
   - Solution: Ensure kernel audit support is enabled

3. **"Failed to create audit client"**
   - Cause: Missing CAP_AUDIT_* capabilities
   - Solution: Run in privileged container or with sudo

4. **"No audit events received"**
   - Cause: Events may be filtered by existing audit rules
   - Solution: Check `auditctl -l` for conflicting rules

### Debugging Commands
```bash
# Check audit status
sudo auditctl -s

# List current rules
sudo auditctl -l

# Check audit logs
sudo tail -f /var/log/audit/audit.log

# Test basic audit functionality
sudo auditctl -w /tmp/test -p wa -k test
touch /tmp/test
sudo auditctl -W /tmp/test -p wa -k test
```

## Architecture Validation

The tests confirm the correct audit architecture:

```
Linux Audit Rules → Kernel Evaluation → Real Audit Events → Direct to Exporters
```

Key architectural benefits verified:
- ✅ No double rule evaluation (kernel pre-filters events)
- ✅ Independent configuration (separate from runtime detection)
- ✅ Direct exporter routing (bypasses rule manager)
- ✅ Real kernel integration (not simulated events)

## Next Steps for Production

1. **Install audit daemon**: `sudo apt install auditd`
2. **Configure capabilities**: Ensure CAP_AUDIT_READ/WRITE
3. **Test rule loading**: Verify rules can be loaded without conflicts
4. **Monitor performance**: Check event volume and processing overhead
5. **Configure exporters**: Set up appropriate alert destinations
