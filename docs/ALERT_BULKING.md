# Alert Bulking Implementation

## Overview

This document describes the alert bulking feature implemented for the node-agent, which allows multiple runtime alerts from the same container to be batched together before being sent to the Kubescape synchronizer.

## Motivation

Previously, the node agent sent each runtime alert individually via the HTTP exporter to the Kubescape synchronizer. With high alert volumes, this created unnecessary HTTP overhead. The existing `HTTPAlertsList` structure already supported multiple alerts, but the agent only sent one alert at a time.

## Key Requirements

1. **Per-Container Bulking**: Bulks must represent a single container - never mix alerts from different pods/containers
2. **Configurable Limits**: Both time-based and size-based flush triggers
3. **Temporal Ordering**: Alerts within a bulk must maintain chronological order
4. **ProcessTree Merging**: Merge process trees from multiple alerts into one comprehensive tree
5. **Container Lifecycle**: Flush pending alerts immediately when a container stops
6. **Backward Compatibility**: Opt-in feature that doesn't affect existing behavior

## Architecture

### High-Level Flow

```
[Alerts] → [Bulk Collection] → [Flush Triggers] → [Send Queue] → [Worker] → [HTTP Send]
            (per container)     (size/timeout)     (FIFO)         (retry)    (with backoff)
```

### Components

#### 1. AlertBulkManager (`pkg/exporters/alert_bulk_manager.go`)

The core component that manages alert bulking:

- **Bulk Storage**: Maintains a map of active bulks per container ID
- **Flush Triggers**:
  - Size limit: Flushes when `BulkMaxAlerts` is reached
  - Timeout: Background goroutine checks every 1 second and flushes bulks older than `BulkTimeoutSeconds`
- **Container Isolation**: Each bulk is scoped to a single `ContainerID`
- **Send Queue**: Buffered channel for pending bulks awaiting transmission
- **Worker Goroutine**: Dedicated goroutine processes queue with retry logic
- **Memory Management**: Bulks are removed immediately after flushing

#### 2. ProcessTree Merger (`pkg/utils/processtree_merge.go`)

Merges process trees from multiple alerts:

- **Tree Traversal**: Recursively walks both process trees
- **Node Merging**: Processes with same PID are enriched with additional information
- **Node Insertion**: New processes are inserted at correct position in tree hierarchy
- **Deduplication**: Ensures each process appears only once

#### 3. Send Queue & Retry Logic

Added in v2.0: Reliable delivery with retry on failure

- **Send Queue**: FIFO channel buffers bulks before sending
- **Retry Mechanism**: Exponential backoff on HTTP failures
- **Metrics**: Comprehensive tracking of queue health and delivery status
- **Graceful Shutdown**: Drains queue before terminating

See [SEND_QUEUE_ARCHITECTURE.md](./SEND_QUEUE_ARCHITECTURE.md) for detailed documentation.

#### 4. Configuration

Added to `HTTPExporterConfig`:

```go
type HTTPExporterConfig struct {
    // ... existing fields ...

    // Alert bulking configuration
    EnableAlertBulking   bool `json:"enableAlertBulking"`    // Enable/disable feature
    BulkMaxAlerts        int  `json:"bulkMaxAlerts"`         // Max alerts per bulk (default: 50)
    BulkTimeoutSeconds   int  `json:"bulkTimeoutSeconds"`    // Max time to collect (default: 10s)

    // Send queue configuration (v2.0+)
    BulkSendQueueSize    int `json:"bulkSendQueueSize"`     // Queue capacity (default: 1000)
    BulkMaxRetries       int `json:"bulkMaxRetries"`        // Max retry attempts (default: 3)
    BulkRetryBaseDelayMs int `json:"bulkRetryBaseDelayMs"`  // Base delay for backoff (default: 1000ms)
    BulkRetryMaxDelayMs  int `json:"bulkRetryMaxDelayMs"`   // Max delay cap (default: 30000ms)
}
```

#### 5. Container Lifecycle Integration

When a container is removed (`EventTypeRemoveContainer`), the RuleManager calls `FlushContainerAlerts()` to immediately send any pending alerts for that container.

## Implementation Details

### Bulk Structure

```go
type containerBulk struct {
    containerID       string
    alerts            []apitypes.RuntimeAlert  // Maintains insertion order
    mergedProcessTree apitypes.Process         // Merged from all alerts
    cloudServices     []string                 // Deduplicated list
    firstAlertTime    time.Time                // When first alert was added
    maxSize           int
    timeoutDuration   time.Duration
}
```

### Flush Logic

A bulk is flushed when:

1. **Size limit reached**: `len(alerts) >= BulkMaxAlerts`
2. **Timeout expired**: `time.Since(firstAlertTime) >= BulkTimeoutSeconds`
3. **Container stopped**: Explicit call to `FlushContainerAlerts(containerID)`
4. **Shutdown**: `Stop()` calls `FlushAll()` to send remaining bulks

### ProcessTree Structure

The `apitypes.ProcessTree` type is a struct wrapping `apitypes.Process`:

```go
type ProcessTree struct {
    ProcessTree Process
    UniqueID    uint32
    ContainerID string
}
```

The actual process tree is in the `ProcessTree` field (nested field with same name as type).

### Merge Algorithm

1. Build a flat map of all PIDs in target tree
2. Traverse source tree recursively
3. For each node:
   - If PID exists in target: enrich with additional info
   - If PID is new: insert at correct position in hierarchy
4. Maintain parent-child relationships via `ChildrenMap`

## Configuration Example

### Basic Configuration

```json
{
  "exporters": {
    "httpExporterConfig": {
      "url": "http://kubescape-synchronizer:8080",
      "enableAlertBulking": true,
      "bulkMaxAlerts": 50,
      "bulkTimeoutSeconds": 10
    }
  }
}
```

### Advanced Configuration (with Send Queue)

```json
{
  "exporters": {
    "httpExporterConfig": {
      "url": "http://kubescape-synchronizer:8080",
      "enableAlertBulking": true,
      "bulkMaxAlerts": 50,
      "bulkTimeoutSeconds": 10,
      "bulkSendQueueSize": 1000,
      "bulkMaxRetries": 3,
      "bulkRetryBaseDelayMs": 1000,
      "bulkRetryMaxDelayMs": 30000
    }
  }
}
```

## Default Values

### Bulk Collection
- `bulkMaxAlerts`: 50 alerts
- `bulkTimeoutSeconds`: 10 seconds
- Flush check interval: 1 second (constant)

### Send Queue (v2.0+)
- `bulkSendQueueSize`: 1000 bulks
- `bulkMaxRetries`: 3 attempts
- `bulkRetryBaseDelayMs`: 1000ms (1 second)
- `bulkRetryMaxDelayMs`: 30000ms (30 seconds)

## Behavior

### Without Bulking (Default)

```
Alert 1 → HTTP Request 1
Alert 2 → HTTP Request 2
Alert 3 → HTTP Request 3
```

### With Bulking Enabled (v1.0)

```
Alert 1 ─┐
Alert 2 ─┤→ (wait 10s or 50 alerts) → HTTP Request (bulk)
Alert 3 ─┘
```

### With Send Queue (v2.0+)

```
Alert 1 ─┐
Alert 2 ─┤→ (collect) → [Queue] → [Worker] → HTTP (with retry)
Alert 3 ─┘                FIFO      retry
                                    on fail
```

**Benefits:**
- ✅ No data loss on transient failures
- ✅ Automatic retry with exponential backoff
- ✅ Ordered delivery per container
- ✅ Backpressure via bounded queue
- ✅ Graceful shutdown drains queue

### Container Termination

```
Alert 1 ─┐
Alert 2 ─┤→ Container stops → Immediate flush → Queue → HTTP (with retry)
Alert 3 ─┘
```

## Testing

### Unit Tests

- `pkg/exporters/alert_bulk_manager_test.go`: Tests bulk manager functionality
- `pkg/utils/processtree_merge_test.go`: Tests process tree merging

Run tests:
```bash
# All bulk manager tests
go test ./pkg/exporters -v -run TestAlertBulkManager

# Send queue tests specifically
go test ./pkg/exporters -v -run TestSendQueue

# ProcessTree merge tests
go test ./pkg/utils -v -run TestMergeProcessTrees

# With race detector
go test -race ./pkg/exporters -run TestAlertBulkManager
```

### Test Coverage

#### Bulk Collection
- Bulk creation and alert addition
- Size-based flushing
- Timeout-based flushing
- Multiple container isolation
- Container-specific flushing
- FlushAll functionality
- ProcessTree merging scenarios
- Cloud services deduplication

#### Send Queue (v2.0+)
- Successful send through queue
- Retry on transient failure
- Max retries exceeded
- Queue full handling
- Graceful shutdown with drain
- Concurrent enqueueing
- Queue metrics accuracy
- Exponential backoff timing

## Performance Considerations

### v1.0 (Basic Bulking)
1. **Memory**: Scales with number of active containers (no hard limit)
2. **CPU**: Background goroutine checks every 1 second (minimal overhead)
3. **Network**: Reduces HTTP requests by up to 50x (depending on alert volume)
4. **Latency**: Alerts may wait up to `BulkTimeoutSeconds` before being sent

### v2.0 (With Send Queue)
1. **Memory**:
   - Bulk map: ~1KB per active container
   - Send queue: ~100KB per bulk × queue size (default ~100MB max)
   - Total: <150MB for typical workloads
2. **CPU**:
   - Background flush goroutine: 1 check/second
   - Send worker goroutine: minimal when idle, active during sends
   - Atomic operations for metrics: negligible overhead
3. **Network**: Same as v1.0, but with retry resilience
4. **Latency**:
   - Normal: Same as v1.0
   - On failure: Additional retry delays (1s, 2s, 4s exponential backoff)
   - Max additional delay: ~7 seconds for 3 retries
5. **Reliability**: ⬆️ Significantly improved with retry logic

## Migration Path

1. **Phase 1**: Deploy with `enableAlertBulking: false` (default)
2. **Phase 2**: Enable in staging environment
3. **Phase 3**: Monitor metrics and adjust `bulkMaxAlerts` and `bulkTimeoutSeconds`
4. **Phase 4**: Roll out to production

## Monitoring

### Available Metrics (v2.0+)

Access via `GetMetrics()` method:

```go
metrics := bulkManager.GetMetrics()
// Returns map[string]int64:
// - "bulks_enqueued": Total bulks added to queue
// - "bulks_sent": Successfully delivered bulks
// - "bulks_failed": Failed after max retries
// - "bulks_retried": Number of retry attempts
// - "bulks_dropped": Dropped due to full queue
// - "queue_depth": Current queue size
// - "max_queue_depth": Peak queue size
// - "active_bulks": Currently collecting bulks
```

### Recommended Monitoring

#### Critical Metrics
- `bulks_dropped`: Should be **0** (non-zero indicates queue pressure)
- `bulks_failed`: Should be **<1%** of enqueued (high indicates backend issues)
- `queue_depth`: Should be **<100** (high indicates processing bottleneck)

#### Health Indicators
- Success rate: `bulks_sent / (bulks_sent + bulks_failed)` should be **>99%**
- Retry rate: `bulks_retried / bulks_enqueued` should be **<5%**
- Drop rate: `bulks_dropped / bulks_enqueued` should be **0%**

#### Performance Metrics
- Average bulk size (alerts per bulk)
- Flush reason distribution (size vs timeout vs container stop)
- Bulk processing latency
- Number of active bulks per node

### Troubleshooting

See [SEND_QUEUE_ARCHITECTURE.md](./SEND_QUEUE_ARCHITECTURE.md#monitoring--troubleshooting) for detailed troubleshooting guide.

## Version History

### v2.0 (Current) - Send Queue Architecture
- ✅ Retry logic with exponential backoff
- ✅ Bounded send queue with backpressure
- ✅ Comprehensive metrics
- ✅ Graceful shutdown with queue draining
- ✅ Race-free implementation
- ✅ Thread-safe metrics with atomic operations

### v1.0 - Basic Bulking
- ✅ Per-container bulk collection
- ✅ Size and timeout-based flushing
- ✅ ProcessTree merging
- ✅ Container lifecycle integration

## Future Enhancements

1. **Dead Letter Queue**: Persist permanently failed bulks to disk
2. **Prometheus Metrics**: Export metrics for monitoring systems
3. **Adaptive Sizing**: Adjust bulk size based on alert rate
4. **Priority Flushing**: Immediate flush for critical severity alerts
5. **Compression**: Compress large bulks before sending
6. **Multi-Worker Mode**: Configurable worker count for high throughput

## Files Modified

- `pkg/exporters/http_exporter.go`: Added bulking configuration and integration
- `pkg/exporters/alert_bulk_manager.go`: New bulk manager component
- `pkg/exporters/exporters_bus.go`: Added FlushContainerAlerts method
- `pkg/rulemanager/v1/rule_manager.go`: Container lifecycle integration
- `pkg/utils/processtree_merge.go`: ProcessTree merging utilities

## Files Created

- `pkg/exporters/alert_bulk_manager_test.go`: Unit tests
- `pkg/utils/processtree_merge_test.go`: Unit tests
- `docs/ALERT_BULKING.md`: This documentation
- `docs/SEND_QUEUE_ARCHITECTURE.md`: Send queue detailed documentation (v2.0)

## Related Documentation

- **[SEND_QUEUE_ARCHITECTURE.md](./SEND_QUEUE_ARCHITECTURE.md)**: Detailed send queue architecture, retry logic, and troubleshooting
- **[RACE_CONDITION_FIX.md](../pkg/exporters/RACE_CONDITION_FIX.md)**: Race condition fix in bulk flushing

