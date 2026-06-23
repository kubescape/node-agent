# Configuration Reference

This document provides a comprehensive reference for all NodeAgent configuration options.

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Environment Variables](#environment-variables)
- [Configuration File Options](#configuration-file-options)
  - [Core Settings](#core-settings)
  - [Feature Toggles](#feature-toggles)
  - [Timing & Performance](#timing--performance)
  - [Filtering Options](#filtering-options)
  - [Exporter Configuration](#exporter-configuration)
  - [Rule Cooldown](#rule-cooldown)
  - [File Integrity Monitoring (FIM)](#file-integrity-monitoring-fim)
  - [Alert Bulking](#alert-bulking)
  - [Advanced Settings](#advanced-settings)
- [Example Configurations](#example-configurations)
- [Validation](#validation)

## Overview

NodeAgent uses [Viper](https://github.com/spf13/viper) for configuration management, supporting:

- JSON configuration files
- Environment variables (auto-mapped)
- Sensible defaults for all options

Configuration is loaded from `/etc/config/config.json` by default, or from the path specified by the `CONFIG_DIR` environment variable.

## Configuration Methods

### 1. Configuration File (Recommended for Kubernetes)

Create a ConfigMap with your configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: node-agent-config
  namespace: kubescape
data:
  config.json: |
    {
      "applicationProfileServiceEnabled": true,
      "runtimeDetectionEnabled": true,
      "malwareDetectionEnabled": true
    }
```

### 2. Environment Variables

All configuration options can be set via environment variables. Viper automatically maps them:

```bash
# Example: Set max image size to 10GB
export MAXIMAGESIZE=10737418240

# Example: Enable runtime detection
export RUNTIMEDETECTIONENABLED=true
```

### 3. Helm Values (Kubernetes)

When deploying via Helm, use the `nodeAgent.config` values:

```bash
helm upgrade --install kubescape kubescape/kubescape-operator \
  --set nodeAgent.config.maxLearningPeriod=15m \
  --set nodeAgent.config.learningPeriod=2m
```

## Environment Variables

These environment variables are read directly (not through config file):

| Variable | Description | Required |
|----------|-------------|----------|
| `NODE_NAME` | Kubernetes node name | Yes (K8s mode) |
| `POD_NAME` | NodeAgent pod name | Yes (K8s mode) |
| `NAMESPACE_NAME` | NodeAgent namespace | Yes (K8s mode) |
| `KUBECONFIG` | Path to kubeconfig file | Standalone only |
| `CONFIG_DIR` | Configuration directory path | No (default: `/etc/config`) |
| `SKIP_KERNEL_VERSION_CHECK` | Skip kernel validation | No |
| `ENABLE_PROFILER` | Enable pprof on port 6060 | No |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (e.g., `otel.armosec.io:4317`). When unset, all telemetry is silently discarded (no-op). | No |
| `OTEL_METRICS_EXPORTER` | Metrics exporter: `otlp` (push to collector) or `prometheus` (expose `:8080/metrics`). Defaults to `otlp` when endpoint is set, `none` otherwise. | No |
| `OTEL_TRACES_EXPORTER` | Traces exporter: `otlp` or `none`. Defaults to `otlp` when endpoint is set, `none` otherwise. | No |
| `OTEL_SLOW_EVAL_THRESHOLD_MS` | Rule evaluations exceeding this threshold (ms) emit a trace span. Default: `5`. | No |
| `OTEL_DEBUG_PORT` | Port for the debug listener when `KS_LOGGER_LEVEL=debug`. Default: `6062`. | No |
| `OTEL_COLLECTOR_SVC` | **Deprecated** — alias for `OTEL_EXPORTER_OTLP_ENDPOINT`. Will be removed in a future release. | No |
| `PYROSCOPE_SERVER_SVC` | Pyroscope server address | No |
| `APPLICATION_NAME` | Application name for Pyroscope | No (default: `node-agent`) |
| `RELEASE` | Release version for telemetry | No |
| `KS_LOGGER_LEVEL` | Log level: `debug`, `info`, `warning`, `error`. Default: `info`. When `debug`, enables the ring-buffer flush endpoint. | No |
| `KS_LOGGER_NAME` | Logger output format: `zap` (structured JSON) or `pretty` (human-readable). Default: `zap`. | No |
| `MULTIPLY` | Enable pod multiplication (testing) | No |
| `QUEUE_DIR` | Directory for persistent queue | No |
| `MAX_QUEUE_SIZE` | Maximum queue size | No |
| `TEST_NAMESPACE` | Override namespace in tests | No |

### OTEL Notes

**Authentication headers:** When credentials are present in `/etc/credentials` (or via `ACCOUNT_ID` /
`ACCESS_KEY` env vars), `X-API-Key` and `X-Customer-GUID` gRPC metadata headers are injected for every
outbound OTLP RPC, regardless of endpoint hostname. This applies to any collector — ARMO back office,
self-hosted, or otherwise. Credentials are read once at startup; agent restart is required if credentials
are rotated at runtime (known v1 limitation).

**Ring buffer (retroactive log export):** When `KS_LOGGER_LEVEL=debug`, the agent keeps the last
7,500 log records in memory and activates a flush endpoint at `localhost:6062/debug/flush-ring-buffer`
(port configurable via `OTEL_DEBUG_PORT`). A `POST` to that endpoint re-emits all buffered records
through the OTLP log pipeline — useful for recovering startup logs that were emitted before the OTLP
exporter finished connecting. The ring buffer is cleared after flushing; a second call emits nothing.

**Kubernetes event correlation — cross-repo dependency (operator PR, not yet implemented)**

K8s events (OOMKilled, Evicted, CrashLoopBackOff, NodeMemoryPressure, pod rescheduling) are collected
by the **operator**, which runs once per cluster and pushes OTLP logs to `otel.armosec.io:4317` using
the same API credentials. Correlation is automatic via shared `k8s.node.name`, `k8s.pod.name`,
`k8s.namespace.name` resource attributes — no node-agent configuration change required.

Until the operator PR ships, node-agent ACs 1–9 are independent and all pass without K8s event
correlation. The ARMO back office dashboard renders correctly using node-agent signals only; K8s event
correlation is an upgrade, not a dependency.

---

## Configuration File Options

### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `nodeName` | string | `$NODE_NAME` | Node name (usually from env) |
| `podName` | string | `$POD_NAME` | Pod name (usually from env) |
| `namespaceName` | string | `$NAMESPACE_NAME` | Namespace (usually from env) |
| `kubernetesMode` | bool | `true` | Enable Kubernetes integration |

### Feature Toggles

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `applicationProfileServiceEnabled` | bool | `false` | Enable application profiling |
| `runtimeDetectionEnabled` | bool | `false` | Enable runtime threat detection |
| `malwareDetectionEnabled` | bool | `false` | Enable ClamAV malware scanning |
| `networkServiceEnabled` | bool | `false` | Enable network connection tracking |
| `networkStreamingEnabled` | bool | `false` | Enable network event streaming |
| `sbomGenerationEnabled` | bool | `false` | Enable SBOM generation |
| `seccompServiceEnabled` | bool | `false` | Enable seccomp profile generation |
| `nodeProfileServiceEnabled` | bool | `false` | Enable node profiling |
| `fimEnabled` | bool | `false` | Enable File Integrity Monitoring |
| `httpDetectionEnabled` | bool | `false` | Enable HTTP traffic parsing |
| `hostMalwareSensorEnabled` | bool | `false` | Enable host-level malware sensor |
| `hostNetworkSensorEnabled` | bool | `false` | Enable host-level network sensor |
| `prometheusExporterEnabled` | bool | `false` | Enable Prometheus metrics |
| `fullPathTracingEnabled` | bool | `true` | Include full executable paths |
| `enableEmbeddedSBOMs` | bool | `false` | Use embedded SBOMs from images |
| `partialProfileGenerationEnabled` | bool | `true` | Allow partial profile generation |
| `ignoreRuleBindings` | bool | `false` | Apply all rules to all pods regardless of bindings. When enabled, RuntimeAlertRuleBinding objects are not watched, every monitored container is kept for runtime detection, and per-pod binding bookkeeping is skipped (rules are resolved directly from the rule creator). |

### Timing & Performance

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `initialDelay` | duration | `2m` | Delay before starting monitors |
| `maxSniffingTimePerContainer` | duration | `24h` | Max time to monitor a container |
| `updateDataPeriod` | duration | `10m` | How often to update storage |
| `nodeProfileInterval` | duration | `10m` | Node profile update interval |
| `networkStreamingInterval` | duration | `2m` | Network streaming batch interval |
| `profilesCacheRefreshRate` | duration | `1m` | Profile cache refresh rate |
| `procfsScanInterval` | duration | `30s` | Procfs scan interval |
| `procfsPidScanInterval` | duration | `5s` | Per-PID procfs scan interval |
| `maxDelaySeconds` | int | `30` | Max random delay for jitter |
| `maxJitterPercentage` | int | `5` | Max jitter percentage |

### Size Limits

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `maxImageSize` | int64 | `5368709120` (5GB) | Max image size to scan |
| `maxSBOMSize` | int | `20971520` (20MB) | Max SBOM size |
| `maxTsProfileSize` | int64 | `2097152` (2MB) | Max TypeScript profile size |

### Worker Pool Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `workerPoolSize` | int | `3000` | Number of worker goroutines |
| `workerChannelSize` | int | `750000` | Worker channel buffer size |
| `eventBatchSize` | int | `15000` | Events processed per batch |
| `blockEvents` | bool | `false` | Block when channel full vs drop |
| `dnsCacheSize` | int | `50000` | DNS cache entry limit |
| `containerEolNotificationBuffer` | int | `100` | Container EOL channel buffer |

### Filtering Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `excludeNamespaces` | []string | `[]` | Namespaces to ignore |
| `includeNamespaces` | []string | `[]` | Only monitor these namespaces |
| `excludeLabels` | map[string][]string | `{}` | Pod labels to exclude |
| `excludeJsonPaths` | []string | `[]` | JSON paths to exclude from profiles |

**Example filtering:**
```json
{
  "excludeNamespaces": ["kube-system", "monitoring"],
  "includeNamespaces": ["production", "staging"],
  "excludeLabels": {
    "app": ["debug-pod", "test-runner"],
    "environment": ["development"]
  }
}
```

### Exporter Configuration

#### HTTP Exporter

```json
{
  "exporters": {
    "httpExporterConfig": {
      "url": "https://api.example.com/v1/runtimealerts",
      "headers": {
        "Authorization": "Bearer <token>"
      },
      "timeoutSeconds": 5,
      "method": "POST"
    }
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exporters::httpExporterConfig::url` | string | - | HTTP endpoint URL |
| `exporters::httpExporterConfig::headers` | map | `{}` | HTTP headers |
| `exporters::httpExporterConfig::timeoutSeconds` | int | `5` | Request timeout |
| `exporters::httpExporterConfig::method` | string | `POST` | HTTP method |

#### AlertManager Exporter

```json
{
  "exporters": {
    "alertManagerExporterUrls": [
      "alertmanager-operated.monitoring.svc.cluster.local:9093"
    ]
  }
}
```

#### Syslog Exporter

```json
{
  "exporters": {
    "syslogExporterURL": "tcp://syslog.example.com:514"
  }
}
```

#### Stdout Exporter

```json
{
  "exporters": {
    "stdoutExporter": true
  }
}
```

### Rule Cooldown

Prevents alert fatigue by limiting how often the same rule fires:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ruleCooldown::ruleCooldownDuration` | duration | `1h` | Cooldown period |
| `ruleCooldown::ruleCooldownAfterCount` | int | `1` | Fire count before cooldown |
| `ruleCooldown::ruleCooldownMaxSize` | int | `10000` | Max cooldown entries |

**Example:**
```json
{
  "ruleCooldown": {
    "ruleCooldownDuration": "30m",
    "ruleCooldownAfterCount": 3,
    "ruleCooldownMaxSize": 5000
  }
}
```

### File Integrity Monitoring (FIM)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `fim::backendConfig::backendType` | string | `fanotify` | FIM backend type |
| `fim::batchConfig::maxBatchSize` | int | `1000` | Max events per batch |
| `fim::batchConfig::batchTimeout` | duration | `1m` | Batch flush timeout |
| `fim::dedupConfig::dedupEnabled` | bool | `true` | Enable deduplication |
| `fim::dedupConfig::dedupTimeWindow` | duration | `5m` | Dedup time window |
| `fim::dedupConfig::maxCacheSize` | int | `1000` | Dedup cache size |
| `fim::periodicConfig::scanInterval` | duration | `5m` | Periodic scan interval |
| `fim::periodicConfig::maxScanDepth` | int | `10` | Max directory depth |
| `fim::periodicConfig::maxSnapshotNodes` | int | `100000` | Max snapshot nodes |
| `fim::periodicConfig::maxFileSize` | int64 | `104857600` (100MB) | Max file size to hash |
| `fim::periodicConfig::includeHidden` | bool | `false` | Include hidden files |
| `fim::periodicConfig::followSymlinks` | bool | `false` | Follow symlinks |

**Example FIM configuration:**
```json
{
  "fimEnabled": true,
  "fim": {
    "directories": [
      {
        "path": "/etc",
        "onCreate": true,
        "onChange": true,
        "onRemove": true,
        "onRename": true,
        "onChmod": true,
        "onMove": true
      },
      {
        "path": "/usr/bin",
        "onChange": true,
        "onCreate": true
      }
    ],
    "backendConfig": {
      "backendType": "fanotify"
    },
    "batchConfig": {
      "maxBatchSize": 500,
      "batchTimeout": "30s"
    },
    "exporters": {
      "stdoutExporter": true,
      "httpExporterConfig": {
        "url": "https://fim-collector.example.com/events"
      }
    }
  }
}
```

### Alert Bulking

Batches alerts for efficient transmission:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exporters::httpExporterConfig::enableAlertBulking` | bool | `false` | Enable alert bulking |
| `exporters::httpExporterConfig::bulkMaxAlerts` | int | `50` | Max alerts per bulk |
| `exporters::httpExporterConfig::bulkTimeoutSeconds` | int | `10` | Bulk flush timeout |
| `exporters::httpExporterConfig::bulkSendQueueSize` | int | `1000` | Send queue capacity |
| `exporters::httpExporterConfig::bulkMaxRetries` | int | `3` | Max retry attempts |
| `exporters::httpExporterConfig::bulkRetryBaseDelayMs` | int | `1000` | Base retry delay |
| `exporters::httpExporterConfig::bulkRetryMaxDelayMs` | int | `30000` | Max retry delay |

See [ALERT_BULKING.md](ALERT_BULKING.md) for detailed documentation.

### Advanced Settings

#### Ordered Event Queue

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `orderedEventQueue::size` | int | `100000` | Queue capacity |
| `orderedEventQueue::collectionDelay` | duration | `50ms` | Event collection delay |

#### Exit Cleanup

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exitCleanup::maxPendingExits` | int | `1000` | Max pending exit events |
| `exitCleanup::cleanupInterval` | duration | `30s` | Cleanup check interval |
| `exitCleanup::cleanupDelay` | duration | `5m` | Delay before cleanup |

#### CEL Configuration Cache

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `celConfigCache::maxSize` | int | `100000` | Cache entry limit |
| `celConfigCache::ttl` | duration | `1m` | Cache entry TTL |

#### Debug Flags

These flags disable specific tracers (useful for debugging):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dCapSys` | bool | `false` | Disable capabilities tracer |
| `dDns` | bool | `false` | Disable DNS tracer |
| `dExec` | bool | `false` | Disable exec tracer |
| `dExit` | bool | `false` | Disable exit tracer |
| `dFork` | bool | `false` | Disable fork tracer |
| `dHardlink` | bool | `false` | Disable hardlink tracer |
| `dHttp` | bool | `false` | Disable HTTP tracer |
| `dIouring` | bool | `false` | Disable io_uring tracer |
| `dNetwork` | bool | `false` | Disable network tracer |
| `dOpen` | bool | `false` | Disable open tracer |
| `dPtrace` | bool | `false` | Disable ptrace tracer |
| `dRandomx` | bool | `false` | Disable RandomX tracer |
| `dSeccomp` | bool | `false` | Disable seccomp tracer |
| `dSsh` | bool | `false` | Disable SSH tracer |
| `dSymlink` | bool | `false` | Disable symlink tracer |
| `dKmod` | bool | `false` | Disable kmod tracer |
| `dUnshare` | bool | `false` | Disable unshare tracer |
| `dBpf` | bool | `false` | Disable BPF tracer |
| `dTop` | bool | `false` | Disable top tracer |
| `testMode` | bool | `false` | Enable test mode |

## Example Configurations

### Minimal Production Setup

```json
{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "networkServiceEnabled": true,
  "exporters": {
    "httpExporterConfig": {
      "url": "https://kubescape-backend.example.com/v1/runtimealerts"
    }
  }
}
```

### Full Security Suite

```json
{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "malwareDetectionEnabled": true,
  "networkServiceEnabled": true,
  "sbomGenerationEnabled": true,
  "seccompServiceEnabled": true,
  "fimEnabled": true,
  "httpDetectionEnabled": true,
  "prometheusExporterEnabled": true,
  "fullPathTracingEnabled": true,
  "initialDelay": "1m",
  "maxImageSize": 10737418240,
  "workerPoolSize": 5000,
  "excludeNamespaces": ["kube-system"],
  "ruleCooldown": {
    "ruleCooldownDuration": "30m",
    "ruleCooldownAfterCount": 5
  },
  "exporters": {
    "httpExporterConfig": {
      "url": "https://api.example.com/v1/runtimealerts",
      "enableAlertBulking": true,
      "bulkMaxAlerts": 100,
      "bulkTimeoutSeconds": 5
    },
    "alertManagerExporterUrls": [
      "alertmanager.monitoring.svc.cluster.local:9093"
    ],
    "stdoutExporter": true
  }
}
```

### Development/Testing Setup

```json
{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "prometheusExporterEnabled": true,
  "testMode": true,
  "initialDelay": "10s",
  "workerPoolSize": 1000,
  "exporters": {
    "stdoutExporter": true
  },
  "ruleCooldown": {
    "ruleCooldownDuration": "1m",
    "ruleCooldownAfterCount": 1
  }
}
```

### High-Throughput Environment

```json
{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "workerPoolSize": 10000,
  "workerChannelSize": 1500000,
  "eventBatchSize": 30000,
  "blockEvents": false,
  "dnsCacheSize": 100000,
  "orderedEventQueue": {
    "size": 200000,
    "collectionDelay": "25ms"
  },
  "exporters": {
    "httpExporterConfig": {
      "url": "https://api.example.com/v1/runtimealerts",
      "enableAlertBulking": true,
      "bulkMaxAlerts": 200,
      "bulkTimeoutSeconds": 3,
      "bulkSendQueueSize": 5000
    }
  }
}
```

## Validation

NodeAgent validates configuration at startup. Common validation errors:

### Missing Required Environment Variables

```
FATAL: NODE_NAME environment variable not set
```

**Solution:** Ensure `NODE_NAME`, `POD_NAME`, and `NAMESPACE_NAME` are set in Kubernetes mode.

### Invalid Duration Format

```
ERROR: time: invalid duration "5minutes"
```

**Solution:** Use Go duration format: `5m`, `30s`, `1h`, etc.

### Configuration File Not Found

```
FATAL: load config error: Config File "config" Not Found
```

**Solution:** Ensure `/etc/config/config.json` exists or set `CONFIG_DIR` appropriately.

### Namespace Filtering Conflict

If both `includeNamespaces` and `excludeNamespaces` are set, `includeNamespaces` takes precedence.

---

For more information, see:
- [Main README](../README.md)
- [Alert Bulking](ALERT_BULKING.md)
- [Kubescape Documentation](https://kubescape.io/docs/)