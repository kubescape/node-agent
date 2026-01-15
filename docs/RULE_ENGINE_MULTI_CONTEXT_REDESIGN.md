# Rule Engine Multi-Context Redesign

## Overview

This document describes the design and implementation of the multi-context rule engine in the Kubescape Node Agent. The system enables runtime security monitoring and alerting across three distinct execution contexts:

1.  **Kubernetes**: Containers running within a Kubernetes cluster (Pod-based).
2.  **Host**: The underlying node itself, treated as a specialized context for monitoring host-level activities.
3.  **Standalone**: Non-Kubernetes containers (e.g., Docker containers, standalone containerd instances) that are not managed by the Kubernetes orchestrator.

## Goals

- Provide a unified rule evaluation engine for all execution contexts.
- Use the mount namespace (mntns) ID as the primary key for identifying event contexts.
- Support multiple container runtimes through automated discovery (fanotify).
- Allow fine-grained control over where rules apply using context-specific tags.
- Maintain backward compatibility with existing Kubernetes-only monitoring and alert formats.

## Architecture

### 1. Event Source Context

The system defines three primary context types in `pkg/contextdetection/types.go`:

```go
type EventSourceContext string

const (
	Kubernetes EventSourceContext = "kubernetes"
	Host       EventSourceContext = "host"
	Standalone EventSourceContext = "standalone"
)
```

### 2. Context Detection and Registry

The architecture relies on a discovery mechanism that identifies the nature of a process or container when it starts.

#### Context Info and Detectors
Each detected context is represented by a `ContextInfo` object which provides the context type and a unique `WorkloadID`.

```go
type ContextInfo interface {
	Context() EventSourceContext
	WorkloadID() string
}
```

The `DetectorManager` coordinates several `ContextDetector` implementations:
- **K8sDetector**: Identifies containers enriched with Kubernetes metadata (Namespace, Pod name).
- **HostDetector**: Identifies the host context based on PID 1 or the host's mount namespace.
- **StandaloneDetector**: Identifies containers that have runtime information but lack Kubernetes metadata.

#### Mount Namespace Registry
The `MntnsRegistry` maintains a thread-safe mapping of mount namespace IDs to their corresponding `ContextInfo`. This registry is the "source of truth" used to enrich eBPF events as they arrive.

```go
type Registry interface {
	Register(mntns uint64, info ContextInfo) error
	Lookup(mntns uint64) (ContextInfo, bool)
	Unregister(mntns uint64)
}
```

### 3. Event Enrichment

As eBPF events (exec, open, network, etc.) are captured, they are wrapped in an `EnrichedEvent`. The `RuleManager` enriches these events with context information by looking up the event's mount namespace ID in the registry.

```go
func (rm *RuleManager) enrichEventWithContext(enrichedEvent *events.EnrichedEvent) {
	mntnsID := enrichedEvent.Event.GetMountNsID()
	enrichedEvent.MountNamespaceID = mntnsID

	if mntnsID != 0 {
		if contextInfo, found := rm.mntnsRegistry.Lookup(mntnsID); found {
			enrichedEvent.SourceContext = contextInfo
		}
	}
}
```

### 4. Rule Evaluation Logic

#### Context-Aware Filtering
Rules can specify where they should execute using the `context:` tag prefix. The `RuleAppliesToContext` function determines if a rule is applicable:

- If a rule has tags like `context:host`, it will only run for events detected as `Host`.
- If a rule has no `context:` tags, it defaults to `Kubernetes` only, ensuring backward compatibility for existing rule sets.

```go
func RuleAppliesToContext(rule *typesv1.Rule, contextInfo contextdetection.ContextInfo) bool {
    // ... logic to check "context:" tags ...
    // Default: return currentContext == contextdetection.Kubernetes
}
```

#### Profile Dependencies
Kubernetes-specific features like Application Profiles and Network Neighborhoods are only enforced for the `Kubernetes` context. Rules requiring these profiles are skipped for `Host` and `Standalone` contexts.

### 5. Alert Structure

The `GenericRuleFailure` structure has been extended to include the `SourceContext`. To maintain compatibility with existing consumers (like the Kubescape Cloud or third-party SIEMs), context-specific metadata is mapped into the existing `RuntimeAlertK8sDetails` structure where appropriate:

- **Host alerts**: The node's hostname is populated in the `NodeName` field.
- **Standalone alerts**: Container ID and Image information are populated, while K8s-specific fields (Namespace, Pod) remain empty.

```go
type GenericRuleFailure struct {
    // ... existing fields ...
    SourceContext contextdetection.EventSourceContext
}
```

### 6. Multiple Runtime Discovery

The Node Agent leverages `inspektor-gadget`'s `WithContainerFanotifyEbpf()` capability. This allows the agent to:
1. Use fanotify to watch for OCI runtime (runc, crun) executions.
2. Capture the container's bundle directory and PID.
3. Automatically detect and monitor containers regardless of whether they were started by `kubelet`, `docker`, or `containerd` directly.

## Configuration

Context monitoring is configurable via the Node Agent configuration:

```yaml
# Enable/disable specific monitoring contexts
hostMonitoringEnabled: true
standaloneMonitoringEnabled: true

# Note: Kubernetes monitoring is usually tied to enableRuntimeDetection
enableRuntimeDetection: true
```

## Implementation Status

- [x] **Core Infrastructure**: Definition of context types and the `MntnsRegistry`.
- [x] **Detector Framework**: Implementation of K8s, Host, and Standalone detectors.
- [x] **Event Enrichment**: Integration into `RuleManager` to attach context to every event.
- [x] **Context-Aware Rules**: Support for `context:` tags in rule definitions.
- [x] **Unified Alerting**: Updated `RuleFailureCreator` to handle multi-context metadata.
- [x] **Multi-Runtime Support**: Integration with fanotify for standalone container discovery.
- [x] **Testing**: Unit and integration tests for context detection and rule application.

## Future Considerations

- **Standalone Profiles**: Extending Application Profile learning to standalone containers.
- **Host Policy**: Specific rule sets tailored for host-level hardening and monitoring.
- **Dynamic Context Tags**: Allowing users to define custom contexts based on container labels or environment variables.