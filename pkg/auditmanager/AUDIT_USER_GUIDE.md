# Node-Agent Audit Feature User Guide

This comprehensive guide will walk you through setting up and using the node-agent audit feature, which provides real-time Linux audit event monitoring and analysis in Kubernetes environments.

## TL;DR - Quick Start

For immediate testing and evaluation:

```bash
# 1. Add Kubescape Helm repository
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# 2. Install with Linux audit enabled
helm install kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --set linuxAudit.enabled=true

# 3. Create a test audit rule
kubectl apply -f - <<EOF
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: test-file-monitoring
  namespace: kubescape
spec:
  enabled: true
  rules:
  - name: test-rule
    description: "Monitor /tmp directory"
    fileWatch:
      paths: ["/tmp"]
      permissions: [read, write]
      keys: ["test_monitoring"]
EOF

# 4. Test the rule
kubectl exec -n kubescape -l app=kubescape-operator -- touch /tmp/test-file

# 5. Check logs for audit events
kubectl logs -n kubescape -l app=kubescape-operator | grep "audit event"
```

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Adding Audit Rules](#adding-audit-rules)
6. [Exporters](#exporters)
7. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
8. [Examples](#examples)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

## Overview

The node-agent audit feature provides:

- **Real-time Linux audit monitoring** using the kernel's audit subsystem
- **Kubernetes-native rule management** via Custom Resource Definitions (CRDs)
- **Multiple export formats** including stdout, HTTP, and auditbeat-compatible formats
- **Kubernetes context enrichment** with pod, namespace, and node information
- **Rate limiting and filtering** to manage event volume
- **Structured rule definitions** for common monitoring scenarios

## Prerequisites

### System Requirements

- **Linux kernel** with audit subsystem enabled
- **Kubernetes cluster** (v1.19+)
- **kubectl** configured to access your cluster
- **Node-agent** deployed with audit feature enabled

### Kernel Audit Subsystem

Ensure the Linux audit subsystem is enabled on your nodes. The audit subsystem is built into the Linux kernel and doesn't require the `auditd` daemon:

```bash
# Check if audit subsystem is enabled in the kernel
sudo auditctl -s

# Expected output should show:
# enabled 1
# failure 1
# pid [some_pid]
# rate_limit 0
# backlog_limit 8192
# lost 0
# backlog 0
# backlog_wait_time 0
# loginuid_immutable 0 unlocked

# If audit is not enabled (enabled 0), you need to enable it in the kernel
# This is typically done at boot time or through kernel parameters
# Check current kernel parameters
cat /proc/cmdline | grep audit

# To enable audit at boot, add to kernel command line:
# audit=1
```

### Enabling Audit in Kubernetes Nodes

For Kubernetes clusters, audit subsystem configuration is typically managed at the node level:

#### Container-Optimized OS (COS) / GKE
```bash
# Check if audit is enabled
sudo auditctl -s

# If not enabled, you may need to configure the node image
# or use a custom node image with audit enabled
```

#### Amazon EKS / Ubuntu Nodes
```bash
# Check current audit status
sudo auditctl -s

# Enable audit subsystem (if not already enabled)
echo 'GRUB_CMDLINE_LINUX_DEFAULT="audit=1"' | sudo tee -a /etc/default/grub
sudo update-grub
sudo reboot
```

#### Custom Node Images
When building custom node images, ensure the kernel command line includes:
```
audit=1
```

#### Verification
After enabling audit, verify it's working:
```bash
# Check audit status
sudo auditctl -s

# Test audit functionality
sudo auditctl -w /tmp/test -p rwxa -k test_rule
sudo touch /tmp/test
sudo auditctl -D  # Remove test rule
```

### Required Permissions

The node-agent requires the following capabilities:
- `CAP_AUDIT_CONTROL` - to manage audit rules
- `CAP_AUDIT_READ` - to read audit events
- `CAP_SYS_ADMIN` - for container context enrichment

## Installation

### Step 1: Install Kubescape Operator with Linux Audit

The Kubescape Operator Helm chart includes the Linux audit feature as an optional capability. Install it with audit monitoring enabled:

```bash
# Add the Kubescape Helm repository
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# Install Kubescape Operator with Linux audit enabled
helm install kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --set linuxAudit.enabled=true
```

### Step 2: Verify Installation

Check that the installation was successful:

```bash
# Verify the CRD is installed
kubectl get crd linuxauditrules.kubescape.io

# Check that the operator is running
kubectl get pods -n kubescape -l app=kubescape-operator

# Verify the node-agent daemonset is running
kubectl get daemonset -n kubescape
```

### Step 3: Configure Audit Detection

The Helm chart automatically configures the node-agent with the required capabilities and settings when `linuxAudit.enabled=true`. The following capabilities are automatically added:

- **`AUDIT_READ`** - Required to read audit events from the kernel
- **`AUDIT_WRITE`** - Required to write audit events
- **`AUDIT_CONTROL`** - Required to manage audit rules and configuration

#### Custom Configuration

For advanced configurations, create a custom values file:

```yaml
# kubescape-audit-values.yaml
linuxAudit:
  enabled: true

# Node agent configuration
nodeAgent:
  config:
    auditDetection:
        enabled: true
        exporters:
        stdoutExporter: true
        httpExporterConfig:
            url: "http://your-siem-endpoint/audit-events"
            timeoutSeconds: 10
        auditbeatExporterConfig:
            url: "http://elasticsearch:9200/auditbeat-events"
            timeoutSeconds: 5
            maxEventsPerMinute: 1000
            batchSize: 10
            enableBatching: true
            resolveIds: true
            warnings: true
            rawMessage: false
        eventFilter:
        includeTypes: []  # Empty means only rule-based events
```

Install with custom values:

```bash
helm install kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --values kubescape-audit-values.yaml
```

## Configuration

### Helm Chart Configuration

The Linux audit feature is configured through the Kubescape Operator Helm chart. The configuration is managed via the `linuxAudit` and `nodeAgent` sections in the values file.

#### Basic Configuration

Enable Linux audit monitoring:

```yaml
# values.yaml
linuxAudit:
  enabled: true
```

#### Advanced Configuration

For detailed configuration of audit detection and exporters:

```yaml
# values.yaml
linuxAudit:
  enabled: true

nodeAgent:
  auditDetection:
    enabled: true
    exporters:
      # Enable stdout exporter for debugging
      stdoutExporter: true

      # Configure HTTP exporter
      httpExporterConfig:
        url: "http://your-siem-endpoint/audit-events"
        timeoutSeconds: 10
        headers:
          - key: "Authorization"
            value: "Bearer your-token"
          - key: "Content-Type"
            value: "application/json"

      # Configure auditbeat exporter
      auditbeatExporterConfig:
        url: "http://elasticsearch:9200/auditbeat-events"
        timeoutSeconds: 5
        maxEventsPerMinute: 1000
        batchSize: 10
        enableBatching: true
        resolveIds: true
        warnings: true
        rawMessage: false

    # Event filtering
    eventFilter:
      # Include specific event types (optional)
      # Empty list means only export rule-based events
      includeTypes: []  # e.g., [1300, 1302] for SYSCALL and PATH events
```

### Updating Configuration

To update the configuration after installation:

```bash
# Update with new values
helm upgrade kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --values your-updated-values.yaml

# Or update specific values
helm upgrade kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --set linuxAudit.enabled=true \
  --set nodeAgent.auditDetection.exporters.stdoutExporter=true
```

## Adding Audit Rules

### Rule Types

The audit feature supports several types of monitoring rules:

1. **File Watch Rules** - Monitor file system access
2. **Syscall Rules** - Monitor system calls
3. **Network Rules** - Monitor network activity (future)
4. **Process Rules** - Monitor process execution
5. **Raw Rules** - Custom auditctl format rules

### Basic File Monitoring

Create a rule to monitor sensitive files:

```yaml
# sensitive-files.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: sensitive-files-monitoring
  namespace: kubescape
spec:
  enabled: true
  rules:
  - name: passwd-monitoring
    description: "Monitor changes to user account file"
    enabled: true
    priority: 100
    fileWatch:
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/group
      permissions:
        - read
        - write
        - attr
      keys:
        - user_accounts
        - security_files
  - name: hosts-monitoring
    description: "Monitor changes to hosts file"
    enabled: true
    priority: 200
    fileWatch:
      paths:
        - /etc/hosts
        - /etc/hostname
      permissions:
        - write
        - attr
      keys:
        - network_config
  rateLimit:
    eventsPerSecond: 50
    burstSize: 100
```

Apply the rule:

```bash
kubectl apply -f sensitive-files.yaml
```

### System Call Monitoring

Monitor specific system calls:

```yaml
# syscall-monitoring.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: syscall-monitoring
  namespace: kubescape
spec:
  enabled: true
  rules:
  - name: execve-monitoring
    description: "Monitor all process executions"
    enabled: true
    priority: 100
    syscall:
      syscalls:
        - execve
        - execveat
      architecture:
        - b64
      action: always
      list: exit
      keys:
        - process_execution
  - name: network-syscalls
    description: "Monitor network-related system calls"
    enabled: true
    priority: 200
    syscall:
      syscalls:
        - connect
        - accept
        - bind
        - listen
      architecture:
        - b64
      action: always
      list: exit
      filters:
        - field: a0
          operator: "="
          value: "2"  # AF_INET
      keys:
        - network_activity
  rateLimit:
    eventsPerSecond: 100
    burstSize: 200
```

### Advanced Filtering

Use filters to narrow down events:

```yaml
# advanced-filtering.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: advanced-filtering
  namespace: kubescape
spec:
  enabled: true
  rules:
  - name: suspicious-commands
    description: "Monitor execution of potentially suspicious commands"
    enabled: true
    priority: 50
    syscall:
      syscalls:
        - execve
      architecture:
        - b64
      action: always
      list: exit
      filters:
        - field: exe
          operator: "="
          value: "/bin/nc"
        - field: exe
          operator: "="
          value: "/usr/bin/wget"
        - field: exe
          operator: "="
          value: "/usr/bin/curl"
        - field: exe
          operator: "="
          value: "/usr/bin/nmap"
      keys:
        - suspicious_execution
  - name: root-activity
    description: "Monitor root user activity"
    enabled: true
    priority: 100
    syscall:
      syscalls:
        - execve
      architecture:
        - b64
      action: always
      list: exit
      filters:
        - field: uid
          operator: "="
          value: "0"
      keys:
        - root_activity
  rateLimit:
    eventsPerSecond: 200
    burstSize: 400
```

### Node-Specific Rules

Target specific nodes using node selectors:

```yaml
# node-specific.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: control-plane-monitoring
  namespace: kubescape
spec:
  enabled: true
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
  rules:
  - name: kube-apiserver-monitoring
    description: "Monitor kube-apiserver file access"
    enabled: true
    fileWatch:
      paths:
        - /etc/kubernetes/manifests
        - /etc/kubernetes/pki
      permissions:
        - read
        - write
        - attr
      keys:
        - kube_apiserver
  rateLimit:
    eventsPerSecond: 100
    burstSize: 200
```

### Raw Audit Rules

For complex scenarios, use raw auditctl format:

```yaml
# raw-rules.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: raw-audit-rules
  namespace: kubescape
spec:
  enabled: true
  rules:
  - name: complex-file-rule
    description: "Complex file monitoring rule"
    enabled: true
    rawRule: "-w /etc/passwd -p rwxa -k user_accounts -F auid>=1000"
  - name: complex-syscall-rule
    description: "Complex syscall monitoring rule"
    enabled: true
    rawRule: "-a always,exit -F arch=b64 -S execve -F key=process_execution -F success=1"
  rateLimit:
    eventsPerSecond: 50
    burstSize: 100
```

## Exporters

The Kubescape Operator supports multiple exporters for audit events. Configure them through the Helm chart values.

### Stdout Exporter

The stdout exporter outputs audit events to the container logs for debugging:

```yaml
# values.yaml
nodeAgent:
  auditDetection:
    exporters:
      stdoutExporter: true
```

### HTTP Exporter

Send events to HTTP endpoints (SIEM systems, webhooks, etc.):

```yaml
# values.yaml
nodeAgent:
  auditDetection:
    exporters:
      httpExporterConfig:
        url: "http://your-siem-endpoint/audit-events"
        method: "POST"
        timeoutSeconds: 10
        headers:
          - key: "Authorization"
            value: "Bearer your-token"
          - key: "Content-Type"
            value: "application/json"
        queryParams:
          - key: "source"
            value: "node-agent"
          - key: "cluster"
            value: "production"
        maxEventsPerMinute: 1000
        batchSize: 10
        enableBatching: true
```

### Auditbeat Exporter

The auditbeat exporter sends events in auditbeat-compatible format, making it easy to integrate with Elasticsearch and other systems that expect auditbeat data.

#### Basic Auditbeat Configuration

```yaml
# values.yaml
nodeAgent:
  auditDetection:
    exporters:
      auditbeatExporterConfig:
        url: "http://elasticsearch:9200/auditbeat-events"
        timeoutSeconds: 5
        maxEventsPerMinute: 2000
        batchSize: 20
        enableBatching: true
        resolveIds: true
        warnings: true
        rawMessage: false
```

#### Advanced Auditbeat Configuration

```yaml
# values.yaml
nodeAgent:
  auditDetection:
    exporters:
      auditbeatExporterConfig:
        url: "http://elasticsearch:9200/auditbeat-events"
        timeoutSeconds: 5
        maxEventsPerMinute: 2000
        batchSize: 20
        enableBatching: true
        resolveIds: true
        warnings: true
        rawMessage: false
        headers:
          - key: "Content-Type"
            value: "application/json"
          - key: "Authorization"
            value: "Bearer your-elasticsearch-token"
        retryAttempts: 3
        retryDelay: "1s"
```

#### Auditbeat Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `url` | Elasticsearch endpoint URL | Required |
| `timeoutSeconds` | HTTP request timeout | 5 |
| `maxEventsPerMinute` | Rate limiting for events | 2000 |
| `batchSize` | Number of events per batch | 20 |
| `enableBatching` | Enable event batching | true |
| `resolveIds` | Resolve user/group IDs to names | true |
| `warnings` | Include warning messages | true |
| `rawMessage` | Include raw audit messages | false |
| `headers` | Custom HTTP headers | [] |
| `retryAttempts` | Number of retry attempts | 3 |
| `retryDelay` | Delay between retries | "1s" |

#### Example: Elasticsearch Integration

For Elasticsearch integration, create an index template and configure the auditbeat exporter:

```yaml
# elasticsearch-auditbeat-values.yaml
nodeAgent:
  auditDetection:
    exporters:
      auditbeatExporterConfig:
        url: "http://elasticsearch:9200/auditbeat-7.17.0"
        timeoutSeconds: 10
        maxEventsPerMinute: 5000
        batchSize: 50
        enableBatching: true
        resolveIds: true
        warnings: true
        rawMessage: false
        headers:
          - key: "Content-Type"
            value: "application/json"
          - key: "Authorization"
            value: "Bearer ${ELASTICSEARCH_TOKEN}"
```

#### Example: Splunk Integration

For Splunk integration via HTTP Event Collector (HEC):

```yaml
# splunk-auditbeat-values.yaml
nodeAgent:
  auditDetection:
    exporters:
      auditbeatExporterConfig:
        url: "https://splunk:8088/services/collector/event"
        timeoutSeconds: 10
        maxEventsPerMinute: 1000
        batchSize: 10
        enableBatching: true
        resolveIds: true
        warnings: false
        rawMessage: false
        headers:
          - key: "Content-Type"
            value: "application/json"
          - key: "Authorization"
            value: "Splunk ${SPLUNK_HEC_TOKEN}"
```

### Syslog Exporter

Send events to syslog:

```yaml
# values.yaml
nodeAgent:
  auditDetection:
    exporters:
      syslogExporterURL: "udp://syslog-server:514"
```

## Monitoring and Troubleshooting

### Check Rule Status

```bash
# List all audit rules
kubectl get linuxauditrules -A

# Get detailed information about a specific rule
kubectl describe linuxauditrule sensitive-files-monitoring -n kubescape

# Check rule status
kubectl get linuxauditrule sensitive-files-monitoring -n kubescape -o yaml
```

### View Operator and Node-Agent Logs

```bash
# Get kubescape-operator pods
kubectl get pods -n kubescape -l app=kubescape-operator

# View operator logs
kubectl logs -n kubescape -l app=kubescape-operator -f

# Get node-agent daemonset pods
kubectl get pods -n kubescape -l app=node-agent

# View node-agent logs
kubectl logs -n kubescape -l app=node-agent -f

# View logs from a specific node
kubectl logs -n kubescape -l app=node-agent --field-selector spec.nodeName=your-node-name
```

### Check Audit Rules on Node

```bash
# SSH to the node
ssh your-node

# Check current audit rules
sudo auditctl -l

# Check audit status
sudo auditctl -s

# View audit logs
sudo tail -f /var/log/audit/audit.log
```

### Verify Events

Test your rules by triggering events:

```bash
# Test file monitoring
sudo touch /etc/passwd

# Test process monitoring
sudo ls /tmp

# Check if events are being generated
kubectl logs -n kubescape -l app=node-agent | grep "audit event"
```

## Examples

### Complete Security Monitoring Setup

```yaml
# security-monitoring.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: security-monitoring
  namespace: kubescape
spec:
  enabled: true
  rules:
  # File system monitoring
  - name: critical-files
    description: "Monitor critical system files"
    fileWatch:
      paths:
        - /etc/passwd
        - /etc/shadow
        - /etc/group
        - /etc/sudoers
        - /etc/ssh/sshd_config
      permissions: [read, write, attr]
      keys: [critical_files]

  # Process monitoring
  - name: privilege-escalation
    description: "Monitor privilege escalation attempts"
    syscall:
      syscalls: [execve, execveat]
      filters:
        - field: uid
          operator: "="
          value: "0"
      keys: [privilege_escalation]

  - name: suspicious-commands
    description: "Monitor suspicious command execution"
    syscall:
      syscalls: [execve]
      filters:
        - field: exe
          operator: "="
          value: "/bin/nc"
        - field: exe
          operator: "="
          value: "/usr/bin/wget"
        - field: exe
          operator: "="
          value: "/usr/bin/curl"
      keys: [suspicious_commands]

  # Network monitoring
  - name: network-connections
    description: "Monitor network connections"
    syscall:
      syscalls: [connect, accept, bind]
      keys: [network_connections]

  rateLimit:
    eventsPerSecond: 500
    burstSize: 1000
```

### Development Environment Setup

```yaml
# dev-monitoring.yaml
apiVersion: kubescape.io/v1
kind: LinuxAuditRule
metadata:
  name: dev-monitoring
  namespace: kubescape
spec:
  enabled: true
  nodeSelector:
    environment: development
  rules:
  - name: dev-file-access
    description: "Monitor development file access"
    fileWatch:
      paths:
        - /home/developer
        - /opt/app
      permissions: [read, write]
      keys: [dev_access]
  rateLimit:
    eventsPerSecond: 100
    burstSize: 200
```

## Best Practices

### Rule Design

1. **Start Simple**: Begin with basic file monitoring rules
2. **Use Appropriate Keys**: Choose meaningful keys for event identification
3. **Set Priorities**: Use priority to control rule application order
4. **Rate Limiting**: Always configure rate limits to prevent event flooding
5. **Node Selectors**: Use node selectors to target specific environments

### Performance Considerations

1. **Rule Complexity**: Keep rules simple to minimize performance impact
2. **Event Volume**: Monitor event volume and adjust rate limits accordingly
3. **Filtering**: Use filters to reduce noise and focus on relevant events
4. **Batch Processing**: Enable batching for high-volume exporters

### Security

1. **Principle of Least Privilege**: Only monitor what you need
2. **Sensitive Data**: Be careful with rules that might capture sensitive information
3. **Access Control**: Ensure proper RBAC for audit rule management
4. **Log Retention**: Configure appropriate log retention policies

### Monitoring

1. **Health Checks**: Monitor node-agent pod health
2. **Event Flow**: Verify events are being generated and exported
3. **Rule Status**: Regularly check rule application status
4. **Performance**: Monitor resource usage and event processing rates

## Troubleshooting

### Common Issues

#### Rules Not Applied

```bash
# Check rule status
kubectl describe linuxauditrule your-rule-name -n kubescape

# Check operator logs
kubectl logs -n kubescape -l app=kubescape-operator | grep -i error

# Check node-agent logs
kubectl logs -n kubescape -l app=node-agent | grep -i error

# Verify audit subsystem
sudo auditctl -s
```

#### No Events Generated

```bash
# Check if rules are active
sudo auditctl -l

# Test rule manually
sudo auditctl -w /tmp/test -p rwxa -k test_rule
sudo touch /tmp/test
sudo auditctl -D  # Remove test rule

# Check audit logs (if auditd is installed)
sudo tail -f /var/log/audit/audit.log

# Or check kernel audit events directly
sudo dmesg | grep audit
```

#### High Event Volume

```bash
# Check rate limiting
kubectl get linuxauditrule your-rule-name -n kubescape -o yaml | grep rateLimit

# Adjust rate limits
kubectl patch linuxauditrule your-rule-name -n kubescape --type='merge' -p='{"spec":{"rateLimit":{"eventsPerSecond":50}}}'
```

#### Exporter Issues

```bash
# Check exporter configuration
kubectl logs -n kubescape -l app=node-agent | grep -i exporter

# Check Helm values
helm get values kubescape-operator -n kubescape

# Test HTTP endpoint
curl -X POST http://your-endpoint/audit-events -H "Content-Type: application/json" -d '{"test":"data"}'

# Check network connectivity from node-agent pod
kubectl exec -n kubescape -l app=node-agent -- curl -I http://your-endpoint

# Check auditbeat exporter specifically
kubectl logs -n kubescape -l app=node-agent | grep -i auditbeat
```

### Debug Mode

Enable debug logging through Helm values:

```yaml
# values.yaml
nodeAgent:
  logLevel: debug
  auditDetection:
    enabled: true
```

Or update existing installation:

```bash
helm upgrade kubescape-operator kubescape/kubescape-operator \
  --namespace kubescape \
  --set nodeAgent.logLevel=debug
```

### Support

For additional support:

1. Check the [node-agent documentation](../../README.md)
2. Review [audit subsystem documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
3. Open an issue in the project repository
4. Check Kubernetes audit logs for RBAC issues

---

This guide provides a comprehensive overview of the node-agent audit feature. Start with basic file monitoring rules and gradually add more complex monitoring as needed. Always test your rules in a development environment before deploying to production.
