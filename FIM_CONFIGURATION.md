# File Integrity Monitoring (FIM) Configuration Guide

This document describes how to configure File Integrity Monitoring (FIM) in the Kubescape Node Agent.

## Overview

The FIM system monitors file system changes and can detect unauthorized modifications, creations, deletions, and other file operations. It supports both fanotify (primary) and fsnotify (fallback) implementations for optimal performance and compatibility.

## Configuration Structure

The FIM configuration is defined in the `fim` section of the main configuration file (`config.json`):

```json
{
  "fim": {
    "enabled": true,
    "directories": [...],
    "batchConfig": {...},
    "dedupConfig": {...},
    "exporters": {...}
  }
}
```

## Configuration Options

### 1. Enable/Disable FIM

```json
{
  "fim": {
    "enabled": true
  }
}
```

- **`enabled`** (boolean): Set to `true` to enable FIM monitoring, `false` to disable it.

### 2. Directory Monitoring

Configure which directories to monitor and what events to track:

```json
{
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
        "path": "/var/log",
        "onCreate": true,
        "onChange": true,
        "onRemove": true,
        "onRename": false,
        "onChmod": false,
        "onMove": false
      }
    ]
  }
}
```

#### Directory Configuration Options

- **`path`** (string): The directory path to monitor (relative to host root)
- **`onCreate`** (boolean): Monitor file creation events
- **`onChange`** (boolean): Monitor file modification events
- **`onRemove`** (boolean): Monitor file deletion events
- **`onRename`** (boolean): Monitor file rename events
- **`onChmod`** (boolean): Monitor file permission/attribute change events
- **`onMove`** (boolean): Monitor file move events

### 3. Batch Configuration

Configure how events are batched for processing:

```json
{
  "fim": {
    "batchConfig": {
      "maxBatchSize": 1000,
      "batchTimeout": "1m"
    }
  }
}
```

#### Batch Configuration Options

- **`maxBatchSize`** (integer): Maximum number of events in a batch (default: 1000)
- **`batchTimeout`** (duration): Maximum time to wait before sending a batch (default: "1m")

### 4. Deduplication Configuration

Configure event deduplication to reduce noise:

```json
{
  "fim": {
    "dedupConfig": {
      "dedupEnabled": true,
      "dedupTimeWindow": "5m",
      "maxCacheSize": 1000
    }
  }
}
```

#### Deduplication Configuration Options

- **`dedupEnabled`** (boolean): Enable/disable deduplication (default: true)
- **`dedupTimeWindow`** (duration): Time window for deduplication (default: "5m")
- **`maxCacheSize`** (integer): Maximum number of events to cache (default: 1000)

### 5. Exporters Configuration

Configure which exporters to use for FIM events:

```json
{
  "fim": {
    "exporters": {
      "stdoutExporter": true,
      "syslogExporterURL": "udp://syslog:514",
      "alertManagerExporterUrls": ["http://alertmanager:9093"],
      "httpExporterConfig": {
        "url": "http://synchronizer:8089/apis/v1/kubescape.io/fim"
      }
    }
  }
}
```

#### Exporter Configuration Options

- **`stdoutExporter`** (boolean): Enable stdout exporter for debugging
- **`syslogExporterURL`** (string): Syslog server URL for FIM events
- **`alertManagerExporterUrls`** (array): Array of AlertManager URLs
- **`httpExporterConfig`** (object): HTTP exporter configuration

## Complete Configuration Example

Here's a complete example configuration:

```json
{
  "applicationProfileServiceEnabled": true,
  "malwareDetectionEnabled": true,
  "fullPathTracingEnabled": true,
  "networkServiceEnabled": true,
  "exporters": {
    "syslogExporterURL": "http://syslog.kubescape.svc.cluster.local:514",
    "stdoutExporter": false,
    "alertManagerExporterUrls": [
      "http://alertmanager.kubescape.svc.cluster.local:9093",
      "http://alertmanager.kubescape.svc.cluster.local:9095"
    ],
    "httpExporterConfig": {
      "url": "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io"
    }
  },
  "fim": {
    "enabled": true,
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
        "path": "/var/log",
        "onCreate": true,
        "onChange": true,
        "onRemove": true,
        "onRename": false,
        "onChmod": false,
        "onMove": false
      },
      {
        "path": "/tmp",
        "onCreate": true,
        "onChange": false,
        "onRemove": true,
        "onRename": false,
        "onChmod": false,
        "onMove": false
      }
    ],
    "batchConfig": {
      "maxBatchSize": 1000,
      "batchTimeout": "1m"
    },
    "dedupConfig": {
      "dedupEnabled": true,
      "dedupTimeWindow": "5m",
      "maxCacheSize": 1000
    },
    "exporters": {
      "stdoutExporter": true,
      "syslogExporterURL": "http://syslog.kubescape.svc.cluster.local:514",
      "alertManagerExporterUrls": ["http://alertmanager.kubescape.svc.cluster.local:9093"],
      "httpExporterConfig": {
        "url": "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io/fim"
      }
    }
  }
}
```

## Best Practices

### 1. Directory Selection

- **Critical System Directories**: Monitor `/etc`, `/usr/bin`, `/usr/sbin` for system integrity
- **Log Directories**: Monitor `/var/log` for log tampering detection
- **Application Directories**: Monitor application-specific directories
- **Avoid High-Volume Directories**: Be cautious with `/tmp`, `/var/cache`, etc.

### 2. Event Type Selection

- **Create/Remove**: Essential for detecting unauthorized file operations
- **Change**: Important for detecting file modifications
- **Rename/Move**: Useful for detecting file hiding or relocation
- **Chmod**: Important for detecting permission changes

### 3. Performance Optimization

- **Batch Size**: Adjust based on event volume (500-2000 events)
- **Batch Timeout**: Balance between latency and efficiency (30s-2m)
- **Deduplication**: Enable to reduce noise from rapid file operations
- **Cache Size**: Adjust based on memory constraints and event patterns

### 4. Monitoring Strategy

- **Start Conservative**: Begin with critical directories and essential event types
- **Monitor Logs**: Watch for FIM-related errors or performance issues
- **Gradual Expansion**: Add more directories and event types as needed
- **Regular Review**: Periodically review and adjust configuration

## Troubleshooting

### Common Issues

1. **High CPU Usage**
   - Reduce batch size
   - Enable deduplication
   - Limit monitored directories
   - Use more specific event types

2. **Memory Issues**
   - Reduce deduplication cache size
   - Decrease batch size
   - Monitor fewer directories

3. **Missing Events**
   - Check if fanotify is available (requires CAP_SYS_ADMIN)
   - Verify directory paths exist
   - Check exporter configuration

4. **Too Many Events**
   - Enable deduplication
   - Increase deduplication time window
   - Be more selective with event types
   - Filter out noisy directories

### Debugging

Enable debug logging to troubleshoot issues:

```bash
# Set log level to debug
export LOG_LEVEL=debug

# Run node-agent with debug output
./node-agent
```

### Performance Monitoring

Monitor FIM performance metrics:

- Event processing rate
- Batch processing times
- Memory usage
- CPU usage
- Deduplication effectiveness

## Security Considerations

1. **Privilege Requirements**: Fanotify requires CAP_SYS_ADMIN capability
2. **Data Sensitivity**: FIM events may contain sensitive file path information
3. **Export Security**: Ensure exporters use secure connections (HTTPS, TLS)
4. **Access Control**: Limit access to FIM configuration and logs
5. **Audit Logging**: Maintain audit logs of FIM configuration changes

## Integration with Other Systems

### AlertManager Integration

FIM events can be sent to AlertManager for alerting:

```json
{
  "fim": {
    "exporters": {
      "alertManagerExporterUrls": ["http://alertmanager:9093"]
    }
  }
}
```

### HTTP Exporter Integration

Send FIM events to external systems via HTTP:

```json
{
  "fim": {
    "exporters": {
      "httpExporterConfig": {
        "url": "https://your-security-platform.com/api/fim-events",
        "headers": [
          {"key": "Authorization", "value": "Bearer your-token"}
        ]
      }
    }
  }
}
```

### Syslog Integration

Send FIM events to syslog for centralized logging:

```json
{
  "fim": {
    "exporters": {
      "syslogExporterURL": "udp://syslog-server:514"
    }
  }
}
```

## Migration from Previous Versions

If upgrading from a version without FIM support:

1. Add the `fim` section to your configuration
2. Start with conservative settings
3. Monitor performance and adjust as needed
4. Gradually expand monitoring scope

## Support

For issues or questions about FIM configuration:

1. Check the troubleshooting section above
2. Review the logs for error messages
3. Verify configuration syntax
4. Test with minimal configuration first
5. Contact support with detailed error information
