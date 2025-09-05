# Periodic FIM Scanner Backend

This document describes the new periodic scanning backend for the File Integrity Monitoring (FIM) sensor, which provides an alternative to the real-time monitoring backends (fanotify and fsnotify).

## Overview

The periodic scanner backend periodically scans directories at configurable intervals, creates snapshots of the file system tree, and detects changes by comparing consecutive snapshots. This approach is similar to how Elastic Filebeat works and provides comprehensive change detection without requiring kernel capabilities.

## Features

- **Periodic Scanning**: Configurable scan intervals (e.g., every 5 minutes)
- **Comprehensive Metadata**: Captures file size, permissions, ownership, timestamps, inodes, and device information
- **Tree-based Comparison**: Efficient tree comparison algorithm for change detection
- **Configurable Limits**: Maximum scan depth, file size limits, and snapshot node count limits
- **Pattern-based Exclusions**: Glob patterns to exclude temporary or system files
- **Symlink Handling**: Optional symlink following with configurable behavior
- **Memory Management**: Automatic cleanup when snapshot limits are exceeded

## Architecture

### Core Components

1. **FileTree**: In-memory representation of directory hierarchy with file metadata
2. **SnapshotManager**: Manages file tree snapshots with size constraints and rotation
3. **TreeComparator**: Detects differences between snapshots and generates change events
4. **HostFimSensorPeriodic**: Main sensor implementation that orchestrates the scanning process

### Data Flow

1. **Initial Scan**: Creates the first snapshot without comparison
2. **Periodic Scans**: Creates new snapshots at configured intervals
3. **Change Detection**: Compares new snapshot with previous snapshot
4. **Event Generation**: Converts detected changes to FIM events
5. **Event Processing**: Sends events through existing batch collector and deduplication pipeline

## Configuration

### Basic Configuration

```go
import "github.com/kubescape/node-agent/pkg/hostfimsensor/v1/config"

// Create periodic scanning configuration
periodicConfig := config.DefaultPeriodicConfig()
periodicConfig.ScanInterval = 5 * time.Minute
periodicConfig.MaxSnapshotNodes = 100000 // 100K file limit

// Create complete FIM configuration
fimConfig := config.HostFimConfig{
    BackendConfig: config.HostFimBackendConfig{
        BackendType: config.FimBackendPeriodic,
    },
    PathConfigs: []config.HostFimPathConfig{
        {
            Path:     "/etc",
            OnCreate: true,
            OnChange: true,
            OnRemove: true,
        },
    },
    BatchConfig: config.HostFimBatchConfig{
        MaxBatchSize: 1000,
        BatchTimeout: time.Minute,
    },
    DedupConfig: config.HostFimDedupConfig{
        DedupEnabled:    true,
        DedupTimeWindow: 5 * time.Minute,
        MaxCacheSize:    1000,
    },
    PeriodicConfig: &periodicConfig,
}
```

### Configuration Options

#### PeriodicConfig

- `ScanInterval`: How often to scan (default: 5 minutes)
- `MaxScanDepth`: Maximum directory depth to scan (default: 10)
- `MaxSnapshotNodes`: Maximum number of nodes in snapshot (default: 100,000)
- `IncludeHidden`: Whether to include hidden files (default: false)
- `ExcludePatterns`: Glob patterns to exclude (default: `["*.tmp", "*.log.*", "*.swp", "*.bak"]`)
- `MaxFileSize`: Maximum file size to track (default: 100MB)
- `FollowSymlinks`: Whether to follow symbolic links (default: false)

#### PathConfig

- `Path`: Directory path to monitor
- `OnCreate`: Detect file creation events
- `OnChange`: Detect file modification events
- `OnRemove`: Detect file deletion events
- `OnRename`: Detect file rename events
- `OnChmod`: Detect permission/attribute changes
- `OnMove`: Detect file move events

## Usage

### Creating a Periodic Scanner

```go
import "github.com/kubescape/node-agent/pkg/hostfimsensor/v1"

// Create sensor with explicit backend selection
sensor, err := hostfimsensor.NewHostFimSensorWithBackend("/", fimConfig, exporter)
if err != nil {
    log.Fatal(err)
}

// Start monitoring
err = sensor.Start()
if err != nil {
    log.Fatal(err)
}

// Stop monitoring
defer sensor.Stop()
```

### Event Types

The periodic scanner detects the following types of changes:

- **Create**: New files or directories
- **Modify**: Changes to file content, permissions, or metadata
- **Delete**: Removed files or directories
- **Move**: Files that appear to have been moved (based on size and timestamp heuristics)

### Event Data

Each FIM event includes:

- **File Information**: Path, size, inode, device, modification time, change time
- **Ownership**: User ID, group ID, permissions
- **Event Information**: Event type, timestamp, file hash (SHA256)
- **Host Information**: Hostname, agent ID

## Performance Considerations

### Memory Usage

- **Snapshot Storage**: Each snapshot stores the complete file tree in memory
- **Node Limits**: Configure `MaxSnapshotNodes` based on available memory
- **Automatic Cleanup**: Old snapshots are automatically cleaned up

### Scan Performance

- **Scan Depth**: Limit `MaxScanDepth` to avoid scanning deeply nested directories
- **File Size Limits**: Use `MaxFileSize` to skip large files that don't need monitoring
- **Exclusion Patterns**: Use `ExcludePatterns` to skip temporary or system files
- **Hidden Files**: Disable `IncludeHidden` to skip hidden files

### Error Handling

- **Snapshot Limits**: If snapshot exceeds `MaxSnapshotNodes`, current snapshot is cleared and error is logged
- **Scan Failures**: Failed scans are logged and retried on the next cycle
- **File Access**: Files that cannot be accessed are logged and skipped

## Comparison with Real-time Backends

| Feature | Periodic Scanner | Fanotify | Fsnotify |
|---------|------------------|-----------|----------|
| **Kernel Requirements** | None | CAP_SYS_ADMIN | None |
| **Real-time Detection** | No (configurable delay) | Yes | Yes |
| **Memory Usage** | Higher (snapshots) | Lower | Lower |
| **CPU Usage** | Periodic spikes | Continuous | Continuous |
| **Comprehensive Detection** | Yes | Yes | Limited |
| **Historical Comparison** | Yes | No | No |
| **File Metadata** | Complete | Complete | Limited |

## Best Practices

1. **Scan Intervals**: Choose scan intervals based on security requirements and system performance
2. **Node Limits**: Set `MaxSnapshotNodes` to prevent memory issues on large file systems
3. **Exclusion Patterns**: Exclude temporary files, logs, and other frequently changing files
4. **Path Selection**: Monitor critical system directories rather than entire file systems
5. **Resource Monitoring**: Monitor memory usage and adjust configuration as needed

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Reduce `MaxSnapshotNodes` or `MaxScanDepth`
2. **Slow Scans**: Increase `ScanInterval` or reduce `MaxScanDepth`
3. **Missing Events**: Check `ExcludePatterns` and file size limits
4. **Permission Errors**: Ensure the agent has read access to monitored directories

### Log Messages

- **"Snapshot exceeds maximum node limit"**: Increase `MaxSnapshotNodes` or reduce scan scope
- **"Could not stat file, skipping"**: Normal for inaccessible files, check permissions if unexpected
- **"File too large, skipping"**: File exceeds `MaxFileSize`, adjust if needed

## Future Enhancements

- **Incremental Scanning**: Only scan changed directories between snapshots
- **Persistent Storage**: Save snapshots to disk for historical analysis
- **Advanced Heuristics**: Better move detection and change classification
- **Parallel Scanning**: Concurrent directory scanning for improved performance
- **Compression**: Compress snapshots to reduce memory usage
