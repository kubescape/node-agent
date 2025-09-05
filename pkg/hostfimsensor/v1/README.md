# Host FIM Sensor
This package provides File Integrity Monitoring (FIM) functionality for the Kubescape Node Agent. The implementation uses `fanotify` for real-time monitoring and `periodic` scanning for comprehensive file system analysis.

## Migration Overview

### Why Fanotify?

The original implementation used the `fsnotify` package, which has limitations when monitoring subdirectories:

1. **Limited Subdirectory Support**: fsnotify requires explicit watching of each subdirectory
2. **Performance**: Multiple watchers needed for deep directory structures
3. **Resource Usage**: Higher memory and CPU usage with many watchers

Fanotify provides several advantages:

1. **Automatic Subdirectory Monitoring**: When monitoring a mount point, fanotify automatically monitors all subdirectories
2. **Better Performance**: Single listener per mount point vs multiple fsnotify watchers
3. **Kernel-level Events**: More efficient event delivery
4. **Rich Event Information**: Additional metadata about file operations

### Implementation Details

#### Architecture

The FIM sensor now uses a hybrid approach:

1. **Primary**: Fanotify implementation (`HostFimSensorFanotify`)
2. **Fallback**: Original fsnotify implementation (`HostFimSensorImpl`)
3. **Automatic Fallback**: If fanotify fails (e.g., missing CAP_SYS_ADMIN), automatically falls back to fsnotify

#### Key Features

- **Batching**: Events are collected and sent in batches for better performance
- **Deduplication**: Prevents duplicate events within a configurable time window
- **Configurable Events**: Support for create, modify, delete, rename, chmod, and move operations
- **Graceful Degradation**: Falls back to fsnotify if fanotify is not available

#### Event Types

The implementation supports the following FIM event types:

- `FimEventTypeCreate`: File creation events
- `FimEventTypeChange`: File modification events
- `FimEventTypeRemove`: File deletion events
- `FimEventTypeRename`: File rename events
- `FimEventTypeChmod`: File permission/attribute change events
- `FimEventTypeMove`: File move events

#### Enhanced Event Data

Each FIM event now includes rich metadata similar to Elastic Filebeat:

**File Information:**
- `Path`: File path (with /host prefix removed)
- `FileSize`: File size in bytes
- `FileInode`: File inode number
- `FileDevice`: Device number
- `FileMtime`: Last modification time
- `FileCtime`: Last status change time
- `Uid`: File owner user ID
- `Gid`: File owner group ID
- `Mode`: File permissions and type

**Process Information:**
- `ProcessPid`: Process ID that triggered the event
- `ProcessName`: Process name
- `ProcessArgs`: Process command line arguments

**Host Information:**
- `HostName`: Hostname of the system
- `AgentId`: Agent identifier

**Event Information:**
- `EventType`: Type of file system event
- `Timestamp`: Event timestamp
- `FileHash`: File hash (if available)

### Usage

#### Basic Usage

```go
import "github.com/kubescape/node-agent/pkg/hostfimsensor/v1"

// Create path configurations
pathConfigs := []HostFimPathConfig{
    {
        Path:     "/etc",
        OnCreate: true,
        OnChange: true,
        OnRemove: true,
    },
}

// Create sensor (automatically chooses fanotify or fsnotify)
sensor := hostfimsensor.NewHostFimSensor("/", pathConfigs, exporter)

// Start monitoring
err := sensor.Start()
if err != nil {
    log.Fatal(err)
}

// Stop monitoring
sensor.Stop()
```

#### Advanced Configuration

```go
// Custom batching configuration
batchConfig := HostFimBatchConfig{
    MaxBatchSize: 500,
    BatchTimeout: 30 * time.Second,
}

// Custom deduplication configuration
dedupConfig := HostFimDedupConfig{
    DedupEnabled:    true,
    DedupTimeWindow: 2 * time.Minute,
    MaxCacheSize:    2000,
}

// Create sensor with custom configuration
sensor := hostfimsensor.NewHostFimSensorWithConfig(
    "/",
    pathConfigs,
    exporter,
    batchConfig,
    dedupConfig,
)
```

### Requirements

#### Fanotify Requirements

To use the fanotify implementation, the following requirements must be met:

1. **Linux Kernel**: 5.1 or later for full feature support
2. **Capabilities**: CAP_SYS_ADMIN capability
3. **Filesystem**: Supported filesystem (ext4, xfs, etc.)

#### Fallback Behavior

If fanotify is not available or fails to initialize, the system automatically falls back to the fsnotify implementation. This ensures compatibility across different environments.

### Performance Considerations

#### Fanotify Performance

- **Memory Usage**: Lower memory usage due to single listener per mount point
- **CPU Usage**: Reduced CPU usage for event processing
- **Event Latency**: Lower latency due to kernel-level event delivery
- **Scalability**: Better scalability with large directory structures

#### Monitoring Recommendations

1. **Mount Point Monitoring**: Monitor entire mount points when possible for better performance
2. **Event Filtering**: Use specific event types to reduce noise
3. **Batch Sizing**: Adjust batch size based on event volume
4. **Deduplication**: Enable deduplication to reduce redundant events

### Troubleshooting

#### Common Issues

1. **CAP_SYS_ADMIN Required**: Fanotify requires elevated privileges
   - Solution: Run with appropriate capabilities or use fallback to fsnotify

2. **Kernel Version**: Older kernels may have limited fanotify support
   - Solution: Upgrade kernel or use fsnotify fallback

3. **Filesystem Support**: Some filesystems may not support all fanotify features
   - Solution: Check filesystem compatibility or use fsnotify

#### Debugging

Enable debug logging to troubleshoot issues:

```go
// The implementation uses kubescape/go-logger for logging
// Set log level to debug to see detailed information
```

### Enhanced Capabilities

#### Rich Event Context

The enhanced FIM implementation now provides context-rich events that enable:

1. **Process Attribution**: Link file changes to the specific process that made them
2. **File Integrity**: Track file size, timestamps, and metadata changes
3. **Host Context**: Include hostname and agent information for correlation
4. **Security Analysis**: Enhanced data for threat detection and incident response

#### Comparison with Industry Standards

The enhanced events now provide similar richness to Elastic Filebeat FIM events:

| Feature | Enhanced FIM | Filebeat FIM |
|---------|-------------|--------------|
| File Path | ✅ | ✅ |
| File Size | ✅ | ✅ |
| File Timestamps | ✅ | ✅ |
| File Permissions | ✅ | ✅ |
| Process Information | ✅ | ✅ |
| Host Information | ✅ | ✅ |
| Event Categorization | ✅ | ✅ |

### Migration Notes

#### Backward Compatibility

The migration maintains full backward compatibility:

- All existing APIs remain unchanged
- Automatic fallback to fsnotify ensures compatibility
- No configuration changes required for existing deployments

#### Testing

The implementation includes comprehensive tests:

- Unit tests for both fanotify and fsnotify implementations
- Integration tests for event processing
- Fallback mechanism testing

Run tests with:

```bash
go test ./pkg/hostfimsensor/v1/ -v
```

### Future Enhancements

Potential improvements for future versions:

1. **Event Filtering**: More granular event filtering capabilities
2. **Performance Optimization**: Further performance improvements
3. **Additional Event Types**: Support for more file system events
4. **Configuration Management**: Enhanced configuration options
