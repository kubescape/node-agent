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

### Components

#### 1. AlertBulkManager (`pkg/exporters/alert_bulk_manager.go`)

The core component that manages alert bulking:

- **Bulk Storage**: Maintains a map of active bulks per container ID
- **Flush Triggers**:
  - Size limit: Flushes when `BulkMaxAlerts` is reached
  - Timeout: Background goroutine checks every 1 second and flushes bulks older than `BulkTimeoutSeconds`
- **Container Isolation**: Each bulk is scoped to a single `ContainerID`
- **Memory Management**: Bulks are removed immediately after flushing

#### 2. ProcessTree Merger (`pkg/utils/processtree_merge.go`)

Merges process trees from multiple alerts:

- **Tree Traversal**: Recursively walks both process trees
- **Node Merging**: Processes with same PID are enriched with additional information
- **Node Insertion**: New processes are inserted at correct position in tree hierarchy
- **Deduplication**: Ensures each process appears only once

#### 3. Configuration

Added to `HTTPExporterConfig`:

```go
type HTTPExporterConfig struct {
    // ... existing fields ...

    // Alert bulking configuration
    EnableAlertBulking bool `json:"enableAlertBulking"`  // Enable/disable feature
    BulkMaxAlerts      int  `json:"bulkMaxAlerts"`        // Max alerts per bulk (default: 50)
    BulkTimeoutSeconds int  `json:"bulkTimeoutSeconds"`   // Max time to collect (default: 10s)
}
```

#### 4. Container Lifecycle Integration

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

## Default Values

- `bulkMaxAlerts`: 50 alerts
- `bulkTimeoutSeconds`: 10 seconds
- Flush check interval: 1 second (constant)

## Behavior

### Without Bulking (Default)

```
Alert 1 → HTTP Request 1
Alert 2 → HTTP Request 2
Alert 3 → HTTP Request 3
```

### With Bulking Enabled

```
Alert 1 ─┐
Alert 2 ─┤→ (wait 10s or 50 alerts) → HTTP Request (bulk)
Alert 3 ─┘
```

### Container Termination

```
Alert 1 ─┐
Alert 2 ─┤→ Container stops → Immediate flush → HTTP Request (bulk)
Alert 3 ─┘
```

## Testing

### Unit Tests

- `pkg/exporters/alert_bulk_manager_test.go`: Tests bulk manager functionality
- `pkg/utils/processtree_merge_test.go`: Tests process tree merging

Run tests:
```bash
go test ./pkg/exporters -v -run TestAlertBulkManager
go test ./pkg/utils -v -run TestMergeProcessTrees
```

### Test Coverage

- Bulk creation and alert addition
- Size-based flushing
- Timeout-based flushing
- Multiple container isolation
- Container-specific flushing
- FlushAll functionality
- ProcessTree merging scenarios
- Cloud services deduplication

## Performance Considerations

1. **Memory**: Scales with number of active containers (no hard limit)
2. **CPU**: Background goroutine checks every 1 second (minimal overhead)
3. **Network**: Reduces HTTP requests by up to 50x (depending on alert volume)
4. **Latency**: Alerts may wait up to `BulkTimeoutSeconds` before being sent

## Migration Path

1. **Phase 1**: Deploy with `enableAlertBulking: false` (default)
2. **Phase 2**: Enable in staging environment
3. **Phase 3**: Monitor metrics and adjust `bulkMaxAlerts` and `bulkTimeoutSeconds`
4. **Phase 4**: Roll out to production

## Monitoring

Recommended metrics to track:

- Average bulk size (alerts per bulk)
- Flush reason distribution (size vs timeout vs container stop)
- Bulk processing latency
- Number of active bulks per node

## Future Enhancements

1. **Adaptive Sizing**: Adjust bulk size based on alert rate
2. **Priority Flushing**: Immediate flush for critical severity alerts
3. **Metrics Integration**: Export bulk statistics to Prometheus
4. **Compression**: Compress large bulks before sending

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

