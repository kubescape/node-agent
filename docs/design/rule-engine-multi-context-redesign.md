# Rule Engine Multi-Context Redesign

## Overview

This document proposes a redesign of the rule engine (`rule_manager.go`) to support monitoring and alerting for three different execution contexts:

1. **Kubernetes Pod Containers** (current implementation)
2. **Host** (the node itself, treated as a virtual container)
3. **Non-Kubernetes Containers** (Docker, docker-compose, containerd standalone)

## Goals

- Enable runtime detection for all three contexts using a unified rule engine
- Maintain backward compatibility with existing Kubernetes monitoring
- Allow rules to be selectively applied to different contexts
- Provide appropriate metadata in alerts based on the event context
- Keep the design extensible for future contexts

## Architecture

### 1. Event Source Context

Define an enumeration to identify the source context of events:

```go
// pkg/utils/context.go

type EventSourceContext string

const (
    // EventSourceK8s represents events from Kubernetes pod containers
    EventSourceK8s EventSourceContext = "kubernetes"
    // EventSourceHost represents events from the host itself
    EventSourceHost EventSourceContext = "host"
    // EventSourceDocker represents events from non-K8s containers (docker, containerd)
    EventSourceDocker EventSourceContext = "docker"
)
```

### 2. Event Interface Hierarchy

Redesign the event interfaces to support different contexts while maintaining common functionality:

```go
// pkg/utils/events.go

// BaseEvent is the minimal interface for all events
type BaseEvent interface {
    GetContainerID() string      // Empty for host events
    GetEventType() EventType
    GetTimestamp() types.Time
    HasDroppedEvents() bool
    Release()
}

// ProcessEvent adds process-related information available in all contexts
type ProcessEvent interface {
    BaseEvent
    GetComm() string
    GetPcomm() string
    GetPID() uint32
    GetPpid() uint32
    GetUid() *uint32
    GetGid() *uint32
    GetMountNsID() uint64
    GetError() int64
    GetExtra() interface{}
    SetExtra(extra interface{})
}

// K8sEvent extends ProcessEvent with Kubernetes-specific metadata
type K8sEvent interface {
    ProcessEvent
    GetNamespace() string
    GetPod() string
    GetPodLabels() map[string]string
    GetContainer() string
    GetContainerImage() string
    GetContainerImageDigest() string
    GetHostNetwork() bool
}

// HostEvent extends ProcessEvent for host-level events
type HostEvent interface {
    ProcessEvent
    GetHostname() string
    GetNodeName() string
}

// DockerEvent extends ProcessEvent for non-K8s container events
type DockerEvent interface {
    ProcessEvent
    GetHostname() string
    GetContainerName() string
    GetContainerImage() string
    GetContainerImageDigest() string
}

// ContextAwareEvent wraps any event with its source context
type ContextAwareEvent interface {
    GetSourceContext() EventSourceContext
    GetEvent() ProcessEvent
}
```

### 3. Enriched Event Redesign

Modify `EnrichedEvent` to carry context information:

```go
// pkg/ebpf/events/enriched_event.go

type EnrichedEvent struct {
    Event         utils.ProcessEvent       // Base event (can be K8sEvent, HostEvent, or DockerEvent)
    SourceContext utils.EventSourceContext // The context this event originated from
    Timestamp     time.Time
    ContainerID   string                   // Empty for host events
    ProcessTree   apitypes.Process
    PID           uint32
    PPID          uint32
    
    // Context-specific identifiers
    WorkloadIdentifier string               // WLID for K8s, hostname for host, hostname/container for docker
}

func (e *EnrichedEvent) GetSourceContext() utils.EventSourceContext {
    return e.SourceContext
}

func (e *EnrichedEvent) IsK8sEvent() bool {
    _, ok := e.Event.(utils.K8sEvent)
    return ok && e.SourceContext == utils.EventSourceK8s
}

func (e *EnrichedEvent) IsHostEvent() bool {
    _, ok := e.Event.(utils.HostEvent)
    return ok && e.SourceContext == utils.EventSourceHost
}

func (e *EnrichedEvent) IsDockerEvent() bool {
    _, ok := e.Event.(utils.DockerEvent)
    return ok && e.SourceContext == utils.EventSourceDocker
}
```

### 4. Rule Binding Extensions

Extend `RuntimeAlertRuleBinding` to support new contexts:

```go
// pkg/rulebindingmanager/types/v1/types.go

type RuntimeAlertRuleBindingSpec struct {
    // Existing fields for K8s
    NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`
    PodSelector       metav1.LabelSelector `json:"podSelector,omitempty"`
    
    // New: Target contexts for this binding
    // If empty, defaults to ["kubernetes"] for backward compatibility
    TargetContexts []EventSourceContext `json:"targetContexts,omitempty"`
    
    // New: Host selector (applies when targetContexts includes "host")
    HostSelector *HostSelector `json:"hostSelector,omitempty"`
    
    // New: Container selector for non-K8s containers
    ContainerSelector *ContainerSelector `json:"containerSelector,omitempty"`
    
    // Rules to apply
    Rules []RuntimeAlertRuleBindingRule `json:"rules"`
}

// HostSelector defines criteria for matching host events
type HostSelector struct {
    // NodeNames is a list of node names to match (supports wildcards)
    NodeNames []string `json:"nodeNames,omitempty"`
    // NodeLabels matches nodes with specific labels (from K8s node object)
    NodeLabels map[string]string `json:"nodeLabels,omitempty"`
}

// ContainerSelector defines criteria for matching non-K8s containers
type ContainerSelector struct {
    // ContainerNames is a list of container name patterns (supports wildcards)
    ContainerNames []string `json:"containerNames,omitempty"`
    // ImagePatterns is a list of image name patterns (supports wildcards)
    ImagePatterns []string `json:"imagePatterns,omitempty"`
    // HostNames limits to specific hosts
    HostNames []string `json:"hostNames,omitempty"`
}
```

Example rule binding YAML:

```yaml
apiVersion: kubescape.io/v1
kind: RuntimeAlertRuleBinding
metadata:
  name: multi-context-rules
spec:
  # Apply to all contexts
  targetContexts:
    - kubernetes
    - host
    - docker
  
  # K8s selectors (only used when targeting kubernetes)
  namespaceSelector:
    matchLabels:
      environment: production
  podSelector: {}
  
  # Host selector (only used when targeting host)
  hostSelector:
    nodeNames:
      - "*"  # All nodes
  
  # Docker container selector (only used when targeting docker)
  containerSelector:
    imagePatterns:
      - "nginx:*"
      - "redis:*"
  
  rules:
    - ruleName: "Unexpected process launched"
    - ruleName: "Crypto mining detection"
```

### 5. Rule Manager Redesign

#### 5.1 Context-Aware Rule Binding Cache

```go
// pkg/rulebindingmanager/rulebindingmanager_interface.go

type RuleBindingCache interface {
    // Existing method - kept for backward compatibility
    ListRulesForPod(namespace, name string) []typesv1.Rule
    
    // New methods for different contexts
    ListRulesForHost(hostname string) []typesv1.Rule
    ListRulesForDockerContainer(hostname, containerName, imageName string) []typesv1.Rule
    
    // Generic method that works with any context
    ListRulesForContext(ctx EventContext) []typesv1.Rule
    
    AddNotifier(*chan RuleBindingNotify)
    GetRuleCreator() rulecreator.RuleCreator
    RefreshRuleBindingsRules()
}

// EventContext encapsulates context-specific identification
type EventContext struct {
    SourceContext EventSourceContext
    
    // K8s context
    Namespace string
    PodName   string
    
    // Host context
    Hostname string
    NodeName string
    
    // Docker context
    ContainerName string
    ImageName     string
}
```

#### 5.2 Rule Manager Structure

```go
// pkg/rulemanager/rule_manager.go

type RuleManager struct {
    cfg                  config.Config
    ruleBindingCache     bindingcache.RuleBindingCache
    ctx                  context.Context
    objectCache          objectcache.ObjectCache
    exporter             exporters.Exporter
    metrics              metricsmanager.MetricsManager
    enricher             types.Enricher
    processManager       processtree.ProcessTreeManager
    celEvaluator         cel.CELRuleEvaluator
    ruleCooldown         *rulecooldown.RuleCooldown
    adapterFactory       *ruleadapters.EventRuleAdapterFactory
    ruleFailureCreator   ruleadapters.RuleFailureCreatorInterface
    rulePolicyValidator  *RulePolicyValidator
    
    // K8s-specific tracking (existing)
    trackedContainers    mapset.Set[string]
    podToWlid            maps.SafeMap[string, string]
    containerIdToShimPid maps.SafeMap[string, uint32]
    containerIdToPid     maps.SafeMap[string, uint32]
    k8sClient            k8sclient.K8sClientInterface
    
    // New: Host tracking
    hostMonitoringEnabled bool
    hostname              string
    
    // New: Docker container tracking
    dockerMonitoringEnabled bool
    trackedDockerContainers mapset.Set[string] // hostname/containerName
}
```

#### 5.3 Context-Aware Event Processing

```go
// pkg/rulemanager/rule_manager.go

func (rm *RuleManager) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
    // Determine event context and get appropriate rules
    eventContext := rm.buildEventContext(enrichedEvent)
    
    // Skip if context is not enabled
    if !rm.isContextEnabled(eventContext.SourceContext) {
        return
    }
    
    rules := rm.ruleBindingCache.ListRulesForContext(eventContext)
    if len(rules) == 0 {
        return
    }
    
    // Get workload identifier based on context
    workloadIdentifier := rm.getWorkloadIdentifier(enrichedEvent, eventContext)
    
    // Check profile availability (only for K8s in phase 1)
    profileExists := false
    if eventContext.SourceContext == utils.EventSourceK8s {
        _, _, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, enrichedEvent.ContainerID)
        profileExists = err == nil
    }
    
    eventType := enrichedEvent.Event.GetEventType()
    for _, rule := range rules {
        if !rule.Enabled {
            continue
        }
        
        // Skip profile-dependent rules for non-K8s contexts
        if eventContext.SourceContext != utils.EventSourceK8s && 
           rule.ProfileDependency == armotypes.Required {
            continue
        }
        
        if !profileExists && rule.ProfileDependency == armotypes.Required {
            continue
        }
        
        // ... rest of rule evaluation logic
        
        if shouldAlert {
            ruleFailure := rm.createContextAwareRuleFailure(
                rule, enrichedEvent, eventContext, workloadIdentifier, message, uniqueID, apChecksum, state)
            if ruleFailure != nil {
                rm.exporter.SendRuleAlert(ruleFailure)
            }
        }
    }
}

func (rm *RuleManager) buildEventContext(enrichedEvent *events.EnrichedEvent) EventContext {
    switch enrichedEvent.SourceContext {
    case utils.EventSourceK8s:
        if k8sEvent, ok := enrichedEvent.Event.(utils.K8sEvent); ok {
            return EventContext{
                SourceContext: utils.EventSourceK8s,
                Namespace:     k8sEvent.GetNamespace(),
                PodName:       k8sEvent.GetPod(),
            }
        }
    case utils.EventSourceHost:
        if hostEvent, ok := enrichedEvent.Event.(utils.HostEvent); ok {
            return EventContext{
                SourceContext: utils.EventSourceHost,
                Hostname:      hostEvent.GetHostname(),
                NodeName:      hostEvent.GetNodeName(),
            }
        }
    case utils.EventSourceDocker:
        if dockerEvent, ok := enrichedEvent.Event.(utils.DockerEvent); ok {
            return EventContext{
                SourceContext: utils.EventSourceDocker,
                Hostname:      dockerEvent.GetHostname(),
                ContainerName: dockerEvent.GetContainerName(),
                ImageName:     dockerEvent.GetContainerImage(),
            }
        }
    }
    return EventContext{}
}

func (rm *RuleManager) getWorkloadIdentifier(enrichedEvent *events.EnrichedEvent, ctx EventContext) string {
    switch ctx.SourceContext {
    case utils.EventSourceK8s:
        podID := utils.CreateK8sPodID(ctx.Namespace, ctx.PodName)
        if wlid, ok := rm.podToWlid.Load(podID); ok {
            return wlid
        }
        return ""
    case utils.EventSourceHost:
        return ctx.Hostname
    case utils.EventSourceDocker:
        return fmt.Sprintf("%s/%s", ctx.Hostname, ctx.ContainerName)
    }
    return ""
}

func (rm *RuleManager) isContextEnabled(ctx utils.EventSourceContext) bool {
    switch ctx {
    case utils.EventSourceK8s:
        return rm.cfg.EnableRuntimeDetection
    case utils.EventSourceHost:
        return rm.hostMonitoringEnabled
    case utils.EventSourceDocker:
        return rm.dockerMonitoringEnabled
    }
    return false
}
```

### 6. Alert/RuleFailure Structure

#### Option A: Extend Existing Structure (Recommended for Phase 1)

Reuse `RuntimeAlertK8sDetails` with optional fields and add context indicator:

```go
// pkg/rulemanager/types/failure.go

type GenericRuleFailure struct {
    BaseRuntimeAlert       apitypes.BaseRuntimeAlert
    AlertType              apitypes.AlertType
    AlertPlatform          apitypes.AlertSourcePlatform
    RuntimeProcessDetails  apitypes.ProcessTree
    TriggerEvent           utils.ProcessEvent  // Changed from EnrichEvent to ProcessEvent
    RuleAlert              apitypes.RuleAlert
    RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails  // Reused, some fields may be empty
    RuleID                 string
    CloudServices          []string
    HttpRuleAlert          apitypes.HttpRuleAlert
    Extra                  interface{}
    
    // New fields
    SourceContext          utils.EventSourceContext
    HostDetails            *RuntimeAlertHostDetails    // Non-nil for host events
    DockerDetails          *RuntimeAlertDockerDetails  // Non-nil for docker events
}

// RuntimeAlertHostDetails contains host-specific alert information
type RuntimeAlertHostDetails struct {
    Hostname string `json:"hostname"`
    NodeName string `json:"nodeName"`
}

// RuntimeAlertDockerDetails contains non-K8s container alert information
type RuntimeAlertDockerDetails struct {
    Hostname      string `json:"hostname"`
    ContainerID   string `json:"containerId"`
    ContainerName string `json:"containerName"`
    Image         string `json:"image"`
    ImageDigest   string `json:"imageDigest,omitempty"`
}
```

Add new `AlertSourcePlatform` values:

```go
// In armotypes package (or local constants)

const (
    AlertSourcePlatformK8s    AlertSourcePlatform = "kubernetes"
    AlertSourcePlatformHost   AlertSourcePlatform = "host"
    AlertSourcePlatformDocker AlertSourcePlatform = "docker"
)
```

#### Option B: Union Type with Context-Specific Details

For a cleaner separation (consider for future refactoring):

```go
type GenericRuleFailure struct {
    BaseRuntimeAlert      apitypes.BaseRuntimeAlert
    AlertType             apitypes.AlertType
    RuntimeProcessDetails apitypes.ProcessTree
    TriggerEvent          utils.ProcessEvent
    RuleAlert             apitypes.RuleAlert
    RuleID                string
    CloudServices         []string
    HttpRuleAlert         apitypes.HttpRuleAlert
    Extra                 interface{}
    
    // Context-specific details (only one will be non-nil)
    ContextDetails ContextDetails
}

type ContextDetails struct {
    SourceContext utils.EventSourceContext
    K8s           *RuntimeAlertK8sDetails    `json:"k8s,omitempty"`
    Host          *RuntimeAlertHostDetails   `json:"host,omitempty"`
    Docker        *RuntimeAlertDockerDetails `json:"docker,omitempty"`
}
```

### 7. Container Callbacks and Tracking

Modify container callbacks to handle different container types:

```go
// pkg/rulemanager/containercallbacks.go

func (rm *RuleManager) ContainerCallback(notif containercollection.PubSubEvent) {
    container := notif.Container
    
    // Determine container context
    context := rm.determineContainerContext(container)
    
    switch context {
    case utils.EventSourceK8s:
        rm.handleK8sContainerCallback(notif)
    case utils.EventSourceHost:
        rm.handleHostCallback(notif)
    case utils.EventSourceDocker:
        rm.handleDockerContainerCallback(notif)
    }
}

func (rm *RuleManager) determineContainerContext(container *containercollection.Container) utils.EventSourceContext {
    // Host container (virtual container for host events)
    if container.Runtime.ContainerID == "" || container.Runtime.ContainerID == "host" {
        return utils.EventSourceHost
    }
    
    // K8s container (has namespace and pod name)
    if container.K8s.Namespace != "" && container.K8s.PodName != "" {
        return utils.EventSourceK8s
    }
    
    // Non-K8s container (Docker, containerd standalone)
    return utils.EventSourceDocker
}

func (rm *RuleManager) handleK8sContainerCallback(notif containercollection.PubSubEvent) {
    // Existing K8s container handling logic
    // ...
}

func (rm *RuleManager) handleHostCallback(notif containercollection.PubSubEvent) {
    if !rm.hostMonitoringEnabled {
        return
    }
    
    switch notif.Type {
    case containercollection.EventTypeAddContainer:
        logger.L().Info("RuleManager - starting host monitoring",
            helpers.String("hostname", rm.hostname))
        // Host doesn't need tracking like containers, it's always "running"
    case containercollection.EventTypeRemoveContainer:
        // Host removal typically means agent shutdown
        logger.L().Info("RuleManager - stopping host monitoring")
    }
}

func (rm *RuleManager) handleDockerContainerCallback(notif containercollection.PubSubEvent) {
    if !rm.dockerMonitoringEnabled {
        return
    }
    
    container := notif.Container
    containerKey := fmt.Sprintf("%s/%s", rm.hostname, container.Runtime.ContainerName)
    
    switch notif.Type {
    case containercollection.EventTypeAddContainer:
        logger.L().Debug("RuleManager - add docker container",
            helpers.String("containerID", container.Runtime.ContainerID),
            helpers.String("containerName", container.Runtime.ContainerName))
        rm.trackedDockerContainers.Add(containerKey)
        
    case containercollection.EventTypeRemoveContainer:
        logger.L().Debug("RuleManager - remove docker container",
            helpers.String("containerID", container.Runtime.ContainerID),
            helpers.String("containerName", container.Runtime.ContainerName))
        rm.trackedDockerContainers.Remove(containerKey)
    }
}
```

### 8. Configuration

Add new configuration options:

```go
// pkg/config/config.go

type Config struct {
    // Existing fields...
    EnableRuntimeDetection bool `mapstructure:"enableRuntimeDetection"`
    
    // New fields for multi-context monitoring
    EnableHostMonitoring   bool `mapstructure:"enableHostMonitoring"`
    EnableDockerMonitoring bool `mapstructure:"enableDockerMonitoring"`
    
    // Optional: Host-specific configuration
    HostMonitoringConfig *HostMonitoringConfig `mapstructure:"hostMonitoring,omitempty"`
    
    // Optional: Docker-specific configuration
    DockerMonitoringConfig *DockerMonitoringConfig `mapstructure:"dockerMonitoring,omitempty"`
}

type HostMonitoringConfig struct {
    // Processes to ignore on host
    IgnoreProcesses []string `mapstructure:"ignoreProcesses"`
    // Paths to ignore on host
    IgnorePaths []string `mapstructure:"ignorePaths"`
}

type DockerMonitoringConfig struct {
    // Container name patterns to ignore
    IgnoreContainers []string `mapstructure:"ignoreContainers"`
    // Image patterns to ignore
    IgnoreImages []string `mapstructure:"ignoreImages"`
}
```

Example configuration:

```yaml
enableRuntimeDetection: true
enableHostMonitoring: true
enableDockerMonitoring: true

hostMonitoring:
  ignoreProcesses:
    - "kubelet"
    - "containerd"
  ignorePaths:
    - "/var/log/*"

dockerMonitoring:
  ignoreContainers:
    - "k8s_*"  # Ignore K8s-managed containers
  ignoreImages:
    - "pause:*"
```

### 9. Rule Manager Interface Updates

```go
// pkg/rulemanager/rule_manager_interface.go

type RuleManagerClient interface {
    // Existing methods
    ContainerCallback(notif containercollection.PubSubEvent)
    HasApplicableRuleBindings(namespace, name string) bool
    HasFinalApplicationProfile(pod *v1.Pod) bool
    IsContainerMonitored(k8sContainerID string) bool
    IsPodMonitored(namespace, pod string) bool
    EvaluatePolicyRulesForEvent(eventType utils.EventType, event utils.K8sEvent) []string
    
    // New methods for multi-context support
    IsHostMonitored() bool
    IsDockerContainerMonitored(hostname, containerName string) bool
    HasApplicableRuleBindingsForContext(ctx EventContext) bool
}
```

## Implementation Phases

### Phase 1: Core Infrastructure
1. Define new event interfaces (`BaseEvent`, `ProcessEvent`, `HostEvent`, `DockerEvent`)
2. Add `EventSourceContext` type and constants
3. Update `EnrichedEvent` to carry context information
4. Add configuration options (`enableHostMonitoring`, `enableDockerMonitoring`)
5. Extend `RuntimeAlertRuleBinding` CRD with new selectors

### Phase 2: Rule Manager Updates
1. Implement `buildEventContext` and context-aware event processing
2. Update `RuleBindingCache` to support new contexts
3. Implement `handleHostCallback` and `handleDockerContainerCallback`
4. Add workload identifier logic for each context

### Phase 3: Alert Structure
1. Add `HostDetails` and `DockerDetails` to `GenericRuleFailure`
2. Update `RuleFailureCreator` to populate context-specific details
3. Add new `AlertSourcePlatform` values
4. Update exporters to handle new alert types

### Phase 4: Testing & Integration
1. Unit tests for each context type
2. Integration tests with container-collection
3. End-to-end tests for rule binding and alerting
4. Documentation updates

## Migration Strategy

1. **Backward Compatibility**: Existing `RuntimeAlertRuleBinding` resources without `targetContexts` will default to `["kubernetes"]`
2. **Gradual Rollout**: New features disabled by default (`enableHostMonitoring: false`, `enableDockerMonitoring: false`)
3. **Alert Format**: Option A (extended structure) maintains compatibility with existing alert consumers

## Future Considerations

1. **Application Profiles for Host/Docker**: Learning mode for non-K8s contexts
2. **Network Neighborhood for Docker**: Tracking container network behavior
3. **Additional Contexts**: VMs, serverless functions, etc.
4. **Rule Templating**: Rules that adapt based on context (e.g., different thresholds for host vs container)

## Diagrams

### Event Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Container Collection (eBPF)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ K8s Pods    │  │ Host Events │  │ Docker Containers       │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
└─────────┼────────────────┼──────────────────────┼───────────────┘
          │                │                      │
          ▼                ▼                      ▼
     ┌────────────────────────────────────────────────┐
     │              Event Handler Factory              │
     │  (Enriches events with context information)    │
     └────────────────────────┬───────────────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   EnrichedEvent   │
                    │ + SourceContext   │
                    └─────────┬─────────┘
                              │
                              ▼
     ┌────────────────────────────────────────────────┐
     │                 Rule Manager                    │
     │  ┌──────────────────────────────────────────┐  │
     │  │  buildEventContext(enrichedEvent)        │  │
     │  │  → K8s: namespace/pod                    │  │
     │  │  → Host: hostname                        │  │
     │  │  → Docker: hostname/containerName        │  │
     │  └──────────────────────────────────────────┘  │
     │                      │                          │
     │                      ▼                          │
     │  ┌──────────────────────────────────────────┐  │
     │  │  ListRulesForContext(eventContext)       │  │
     │  │  (Filters by TargetContexts + Selectors) │  │
     │  └──────────────────────────────────────────┘  │
     │                      │                          │
     │                      ▼                          │
     │  ┌──────────────────────────────────────────┐  │
     │  │  Evaluate Rules (CEL)                    │  │
     │  │  Skip profile-dependent for non-K8s      │  │
     │  └──────────────────────────────────────────┘  │
     │                      │                          │
     │                      ▼                          │
     │  ┌──────────────────────────────────────────┐  │
     │  │  Create Context-Aware RuleFailure        │  │
     │  │  + HostDetails / DockerDetails           │  │
     │  └──────────────────────────────────────────┘  │
     └────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │     Exporter      │
                    └───────────────────┘
```

### Rule Binding Resolution

```
┌─────────────────────────────────────────────────────────────┐
│                   RuntimeAlertRuleBinding                    │
├─────────────────────────────────────────────────────────────┤
│ targetContexts: [kubernetes, host, docker]                  │
│                                                             │
│ namespaceSelector: ...    ─┐                                │
│ podSelector: ...           ├─► Used when context = k8s     │
│                           ─┘                                │
│                                                             │
│ hostSelector:             ─┐                                │
│   nodeNames: [*]           ├─► Used when context = host    │
│                           ─┘                                │
│                                                             │
│ containerSelector:        ─┐                                │
│   imagePatterns: [nginx*]  ├─► Used when context = docker  │
│   containerNames: [web*]  ─┘                                │
│                                                             │
│ rules:                                                      │
│   - ruleName: "Crypto mining detection"                     │
│   - ruleID: "R1000"                                         │
└─────────────────────────────────────────────────────────────┘
```
