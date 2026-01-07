# Rule Engine Multi-Context Redesign

## Overview

This document proposes a redesign of the rule engine (`rule_manager.go`) to support monitoring and alerting for three different execution contexts:

1. **Kubernetes Pod Containers** (current implementation)
2. **Host** (the node itself, treated as a virtual container)
3. **Non-Kubernetes Containers** (Docker, docker-compose, containerd standalone)

## Goals

- Enable runtime detection for all three contexts using a unified rule engine
- Maintain backward compatibility with existing Kubernetes monitoring
- Use mount namespace (mntns) as the primary identifier for context type
- Provide appropriate metadata in alerts based on the event context
- Keep the design extensible for future contexts
- Support multiple container runtimes via fanotify-based container discovery

## Key Design Decisions

1. **Mount Namespace Tracking**: Use mount namespace ID as the primary key to classify events into their context type (K8s, Host, Docker)
2. **Simplified Rule Matching**: All rules are evaluated for all contexts by default - no need for rule bindings to specify which contexts to check
3. **Container Collection**: Leverage inspektor-gadget's container-collection for all event sources
4. **Multiple Runtime Support**: Use fanotify to watch multiple runc instances for non-K8s container discovery

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

### 2. Mount Namespace Registry

The core of the design is a registry that maps mount namespace IDs to their context type:

```go
// pkg/rulemanager/mntns_registry.go

type MntnsRegistry struct {
    mu sync.RWMutex
    
    // Mount namespace to context type mapping
    mntnsToContext maps.SafeMap[uint64, EventSourceContext]
    
    // K8s-specific data (only for K8s containers)
    mntnsToK8sInfo maps.SafeMap[uint64, *K8sContainerInfo]
    
    // Docker-specific data (only for non-K8s containers)
    mntnsToDockerInfo maps.SafeMap[uint64, *DockerContainerInfo]
    
    // Host mount namespace ID (set once at startup)
    hostMntns uint64
}

type K8sContainerInfo struct {
    Namespace       string
    PodName         string
    ContainerName   string
    ContainerID     string
    Wlid            string
    PodLabels       map[string]string
    ContainerImage  string
    ContainerImageDigest string
}

type DockerContainerInfo struct {
    Hostname        string
    ContainerID     string
    ContainerName   string
    ContainerImage  string
    ContainerImageDigest string
}

func NewMntnsRegistry(hostMntns uint64) *MntnsRegistry {
    registry := &MntnsRegistry{
        hostMntns: hostMntns,
    }
    // Register host mount namespace
    registry.mntnsToContext.Set(hostMntns, EventSourceHost)
    return registry
}

func (r *MntnsRegistry) RegisterK8sContainer(mntns uint64, info *K8sContainerInfo) {
    r.mntnsToContext.Set(mntns, EventSourceK8s)
    r.mntnsToK8sInfo.Set(mntns, info)
}

func (r *MntnsRegistry) RegisterDockerContainer(mntns uint64, info *DockerContainerInfo) {
    r.mntnsToContext.Set(mntns, EventSourceDocker)
    r.mntnsToDockerInfo.Set(mntns, info)
}

func (r *MntnsRegistry) Unregister(mntns uint64) {
    r.mntnsToContext.Delete(mntns)
    r.mntnsToK8sInfo.Delete(mntns)
    r.mntnsToDockerInfo.Delete(mntns)
}

func (r *MntnsRegistry) GetContext(mntns uint64) (EventSourceContext, bool) {
    return r.mntnsToContext.Load(mntns)
}

func (r *MntnsRegistry) IsHost(mntns uint64) bool {
    return mntns == r.hostMntns
}
```

### 3. Container Callback with Context Detection

The container callback detects the container type and registers it in the mount namespace registry:

```go
// pkg/rulemanager/containercallbacks.go

func (rm *RuleManager) ContainerCallback(notif containercollection.PubSubEvent) {
    container := notif.Container
    mntns := container.Mntns
    
    // Determine container context based on container metadata
    context := rm.determineContainerContext(container)
    
    switch notif.Type {
    case containercollection.EventTypeAddContainer:
        rm.handleContainerAdd(container, mntns, context)
    case containercollection.EventTypeRemoveContainer:
        rm.handleContainerRemove(container, mntns, context)
    }
}

func (rm *RuleManager) determineContainerContext(container *containercollection.Container) EventSourceContext {
    // Host container (virtual container for host events)
    // Host has mntns == 0 or matches the host's mount namespace
    if container.Mntns == 0 || rm.mntnsRegistry.IsHost(container.Mntns) {
        return EventSourceHost
    }
    
    // K8s container (has namespace and pod name)
    if container.K8s.Namespace != "" && container.K8s.PodName != "" {
        return EventSourceK8s
    }
    
    // Non-K8s container (Docker, containerd standalone)
    return EventSourceDocker
}

func (rm *RuleManager) handleContainerAdd(container *containercollection.Container, mntns uint64, ctx EventSourceContext) {
    switch ctx {
    case EventSourceK8s:
        if rm.cfg.IgnoreContainer(container.K8s.Namespace, container.K8s.PodName, container.K8s.PodLabels) {
            return
        }
        
        info := &K8sContainerInfo{
            Namespace:      container.K8s.Namespace,
            PodName:        container.K8s.PodName,
            ContainerName:  container.K8s.ContainerName,
            ContainerID:    container.Runtime.ContainerID,
            PodLabels:      container.K8s.PodLabels,
            // Wlid, image info populated from shared data
        }
        rm.mntnsRegistry.RegisterK8sContainer(mntns, info)
        
        // Existing K8s container handling
        k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
        rm.trackedContainers.Add(k8sContainerID)
        go rm.startRuleManager(container, k8sContainerID)
        
    case EventSourceHost:
        if !rm.hostMonitoringEnabled {
            return
        }
        // Host is always "registered" - no additional tracking needed
        logger.L().Info("RuleManager - host monitoring active", helpers.String("hostname", rm.hostname))
        
    case EventSourceDocker:
        if !rm.dockerMonitoringEnabled {
            return
        }
        
        info := &DockerContainerInfo{
            Hostname:       rm.hostname,
            ContainerID:    container.Runtime.ContainerID,
            ContainerName:  container.Runtime.ContainerName,
            ContainerImage: container.Runtime.ContainerImageName,
        }
        rm.mntnsRegistry.RegisterDockerContainer(mntns, info)
        
        containerKey := fmt.Sprintf("%s/%s", rm.hostname, container.Runtime.ContainerName)
        rm.trackedDockerContainers.Add(containerKey)
        
        logger.L().Debug("RuleManager - add docker container",
            helpers.String("containerID", container.Runtime.ContainerID),
            helpers.String("containerName", container.Runtime.ContainerName),
            helpers.Uint64("mntns", mntns))
    }
}

func (rm *RuleManager) handleContainerRemove(container *containercollection.Container, mntns uint64, ctx EventSourceContext) {
    // Unregister from mntns registry
    rm.mntnsRegistry.Unregister(mntns)
    
    switch ctx {
    case EventSourceK8s:
        // Existing K8s cleanup logic
        k8sContainerID := utils.CreateK8sContainerID(container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
        rm.trackedContainers.Remove(k8sContainerID)
        // ... pod cleanup logic
        
    case EventSourceDocker:
        containerKey := fmt.Sprintf("%s/%s", rm.hostname, container.Runtime.ContainerName)
        rm.trackedDockerContainers.Remove(containerKey)
    }
}
```

### 4. Event Interface Hierarchy

Redesign the event interfaces to support different contexts while maintaining common functionality:

```go
// pkg/utils/events.go

// BaseEvent is the minimal interface for all events
type BaseEvent interface {
    GetContainerID() string      // Empty for host events
    GetEventType() EventType
    GetTimestamp() types.Time
    GetMountNsID() uint64        // Key for context lookup
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
    GetError() int64
    GetExtra() interface{}
    SetExtra(extra interface{})
}

// K8sEvent extends ProcessEvent with Kubernetes-specific metadata
// This is populated by looking up K8sContainerInfo from the registry
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
```

### 5. Enriched Event with Context

```go
// pkg/ebpf/events/enriched_event.go

type EnrichedEvent struct {
    Event         utils.ProcessEvent
    SourceContext utils.EventSourceContext
    Timestamp     time.Time
    ContainerID   string
    ProcessTree   apitypes.Process
    PID           uint32
    PPID          uint32
    MountNsID     uint64
    
    // Workload identifier (varies by context)
    // K8s: WLID
    // Host: hostname
    // Docker: hostname/containerName
    WorkloadIdentifier string
}

func NewEnrichedEventFromMntns(
    event utils.ProcessEvent,
    registry *MntnsRegistry,
    timestamp time.Time,
    processTree apitypes.Process,
) *EnrichedEvent {
    mntns := event.GetMountNsID()
    ctx, _ := registry.GetContext(mntns)
    
    enriched := &EnrichedEvent{
        Event:         event,
        SourceContext: ctx,
        Timestamp:     timestamp,
        MountNsID:     mntns,
        ProcessTree:   processTree,
        PID:           event.GetPID(),
        PPID:          event.GetPpid(),
    }
    
    // Set context-specific fields
    switch ctx {
    case utils.EventSourceK8s:
        if info, ok := registry.mntnsToK8sInfo.Load(mntns); ok {
            enriched.ContainerID = info.ContainerID
            enriched.WorkloadIdentifier = info.Wlid
        }
    case utils.EventSourceHost:
        enriched.WorkloadIdentifier = registry.hostname
    case utils.EventSourceDocker:
        if info, ok := registry.mntnsToDockerInfo.Load(mntns); ok {
            enriched.ContainerID = info.ContainerID
            enriched.WorkloadIdentifier = fmt.Sprintf("%s/%s", info.Hostname, info.ContainerName)
        }
    }
    
    return enriched
}
```

### 6. Rule Manager Redesign

```go
// pkg/rulemanager/rule_manager.go

type RuleManager struct {
    cfg                  config.Config
    ctx                  context.Context
    
    // Mount namespace registry - THE source of truth for context
    mntnsRegistry        *MntnsRegistry
    
    // Rule evaluation
    ruleBindingCache     bindingcache.RuleBindingCache
    celEvaluator         cel.CELRuleEvaluator
    ruleCooldown         *rulecooldown.RuleCooldown
    adapterFactory       *ruleadapters.EventRuleAdapterFactory
    ruleFailureCreator   ruleadapters.RuleFailureCreatorInterface
    rulePolicyValidator  *RulePolicyValidator
    
    // Caches and clients
    objectCache          objectcache.ObjectCache
    exporter             exporters.Exporter
    metrics              metricsmanager.MetricsManager
    enricher             types.Enricher
    processManager       processtree.ProcessTreeManager
    k8sClient            k8sclient.K8sClientInterface
    
    // K8s-specific tracking (existing)
    trackedContainers    mapset.Set[string]
    podToWlid            maps.SafeMap[string, string]
    containerIdToShimPid maps.SafeMap[string, uint32]
    containerIdToPid     maps.SafeMap[string, uint32]
    
    // Host monitoring
    hostMonitoringEnabled bool
    hostname              string
    
    // Docker container tracking
    dockerMonitoringEnabled  bool
    trackedDockerContainers  mapset.Set[string] // hostname/containerName
}

func (rm *RuleManager) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
    ctx := enrichedEvent.SourceContext
    
    // Skip if context is not enabled
    if !rm.isContextEnabled(ctx) {
        return
    }
    
    // Get rules based on context
    rules := rm.getRulesForContext(enrichedEvent)
    if len(rules) == 0 {
        return
    }
    
    // Check profile availability (only for K8s in phase 1)
    var profileExists bool
    var apChecksum string
    if ctx == utils.EventSourceK8s {
        _, apChecksum, err := profilehelper.GetContainerApplicationProfile(rm.objectCache, enrichedEvent.ContainerID)
        profileExists = err == nil
    }
    
    eventType := enrichedEvent.Event.GetEventType()
    for _, rule := range rules {
        if !rule.Enabled {
            continue
        }
        
        // Skip profile-dependent rules for non-K8s contexts (Phase 1)
        if ctx != utils.EventSourceK8s && rule.ProfileDependency == armotypes.Required {
            continue
        }
        
        if !profileExists && rule.ProfileDependency == armotypes.Required {
            continue
        }
        
        ruleExpressions := rm.getRuleExpressions(rule, eventType)
        if len(ruleExpressions) == 0 {
            continue
        }
        
        // Rule policy validation only for K8s
        if ctx == utils.EventSourceK8s && rule.SupportPolicy {
            if rm.validateRulePolicy(rule, enrichedEvent.Event, enrichedEvent.ContainerID) {
                continue
            }
        }
        
        startTime := time.Now()
        shouldAlert, err := rm.evaluateRule(enrichedEvent, eventType, rule)
        evaluationTime := time.Since(startTime)
        rm.metrics.ReportRuleEvaluationTime(rule.Name, eventType, evaluationTime)
        
        if err != nil {
            logger.L().Error("RuleManager.ReportEnrichedEvent - failed to evaluate rule",
                helpers.Error(err),
                helpers.String("rule", rule.ID),
                helpers.String("eventType", string(eventType)),
                helpers.String("context", string(ctx)))
            continue
        }
        
        if shouldAlert {
            rm.handleAlert(enrichedEvent, rule, apChecksum)
        }
        
        rm.metrics.ReportRuleProcessed(rule.Name)
    }
}

func (rm *RuleManager) getRulesForContext(enrichedEvent *events.EnrichedEvent) []typesv1.Rule {
    switch enrichedEvent.SourceContext {
    case utils.EventSourceK8s:
        // Use existing K8s rule binding logic
        if info, ok := rm.mntnsRegistry.mntnsToK8sInfo.Load(enrichedEvent.MountNsID); ok {
            return rm.ruleBindingCache.ListRulesForPod(info.Namespace, info.PodName)
        }
        return nil
        
    case utils.EventSourceHost:
        // For host, return all rules (filtered by profile dependency later)
        return rm.ruleBindingCache.GetRuleCreator().CreateAllRules()
        
    case utils.EventSourceDocker:
        // For docker, return all rules (could add filtering by image/name later)
        return rm.ruleBindingCache.GetRuleCreator().CreateAllRules()
    }
    return nil
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

func (rm *RuleManager) handleAlert(enrichedEvent *events.EnrichedEvent, rule typesv1.Rule, apChecksum string) {
    state := rule.State
    eventType := enrichedEvent.Event.GetEventType()
    
    if eventType == utils.HTTPEventType {
        state = rm.evaluateHTTPPayloadState(rule.State, enrichedEvent)
    }
    
    rm.metrics.ReportRuleAlert(rule.Name)
    
    message, uniqueID, err := rm.getUniqueIdAndMessage(enrichedEvent, rule)
    if err != nil {
        logger.L().Error("RuleManager - failed to get unique ID and message", helpers.Error(err))
        return
    }
    
    if shouldCooldown, _ := rm.ruleCooldown.ShouldCooldown(uniqueID, enrichedEvent.ContainerID, rule.ID); shouldCooldown {
        return
    }
    
    ruleFailure := rm.createContextAwareRuleFailure(enrichedEvent, rule, message, uniqueID, apChecksum, state)
    if ruleFailure == nil {
        return
    }
    
    rm.exporter.SendRuleAlert(ruleFailure)
}
```

### 7. Alert/RuleFailure Structure

#### Option A: Extend Existing Structure (Recommended for Phase 1)

Reuse `RuntimeAlertK8sDetails` with optional fields and add context-specific details:

```go
// pkg/rulemanager/types/failure.go

type GenericRuleFailure struct {
    BaseRuntimeAlert       apitypes.BaseRuntimeAlert
    AlertType              apitypes.AlertType
    AlertPlatform          apitypes.AlertSourcePlatform
    RuntimeProcessDetails  apitypes.ProcessTree
    TriggerEvent           utils.ProcessEvent
    RuleAlert              apitypes.RuleAlert
    RuntimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails  // Reused, some fields empty for non-K8s
    RuleID                 string
    CloudServices          []string
    HttpRuleAlert          apitypes.HttpRuleAlert
    Extra                  interface{}
    
    // New fields for context identification
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

// AlertSourcePlatform values
const (
    AlertSourcePlatformK8s    apitypes.AlertSourcePlatform = "kubernetes"
    AlertSourcePlatformHost   apitypes.AlertSourcePlatform = "host"
    AlertSourcePlatformDocker apitypes.AlertSourcePlatform = "docker"
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
    SourceContext utils.EventSourceContext  `json:"sourceContext"`
    K8s           *RuntimeAlertK8sDetails   `json:"k8s,omitempty"`
    Host          *RuntimeAlertHostDetails  `json:"host,omitempty"`
    Docker        *RuntimeAlertDockerDetails `json:"docker,omitempty"`
}
```

### 8. Rule Failure Creator Updates

```go
// pkg/rulemanager/ruleadapters/creator.go

func (r *RuleFailureCreator) createContextAwareRuleFailure(
    enrichedEvent *events.EnrichedEvent,
    rule typesv1.Rule,
    message, uniqueID, apChecksum string,
    state map[string]any,
) types.RuleFailure {
    
    ctx := enrichedEvent.SourceContext
    
    ruleFailure := &types.GenericRuleFailure{
        BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
            UniqueID:    uniqueID,
            AlertName:   rule.Name,
            Severity:    rule.Severity,
            Arguments:   map[string]interface{}{
                "apChecksum": apChecksum,
                "message":    message,
            },
            Timestamp:   enrichedEvent.Timestamp,
            InfectedPID: enrichedEvent.ProcessTree.PID,
        },
        RuleAlert: apitypes.RuleAlert{
            RuleDescription: message,
        },
        RuleID:        rule.ID,
        SourceContext: ctx,
    }
    
    // Set platform and context-specific details
    switch ctx {
    case utils.EventSourceK8s:
        ruleFailure.AlertPlatform = AlertSourcePlatformK8s
        r.setRuntimeAlertK8sDetails(ruleFailure, enrichedEvent)
        
    case utils.EventSourceHost:
        ruleFailure.AlertPlatform = AlertSourcePlatformHost
        ruleFailure.HostDetails = &RuntimeAlertHostDetails{
            Hostname: enrichedEvent.WorkloadIdentifier,
            NodeName: r.nodeName,
        }
        // Set minimal K8s details for compatibility
        ruleFailure.RuntimeAlertK8sDetails = apitypes.RuntimeAlertK8sDetails{
            NodeName: r.nodeName,
        }
        
    case utils.EventSourceDocker:
        ruleFailure.AlertPlatform = AlertSourcePlatformDocker
        if info, ok := r.mntnsRegistry.mntnsToDockerInfo.Load(enrichedEvent.MountNsID); ok {
            ruleFailure.DockerDetails = &RuntimeAlertDockerDetails{
                Hostname:      info.Hostname,
                ContainerID:   info.ContainerID,
                ContainerName: info.ContainerName,
                Image:         info.ContainerImage,
                ImageDigest:   info.ContainerImageDigest,
            }
            // Set minimal K8s details for compatibility
            ruleFailure.RuntimeAlertK8sDetails = apitypes.RuntimeAlertK8sDetails{
                NodeName:      r.nodeName,
                ContainerID:   info.ContainerID,
                ContainerName: info.ContainerName,
                Image:         info.ContainerImage,
            }
        }
    }
    
    // Common processing
    r.setBaseRuntimeAlert(ruleFailure)
    
    if enrichedEvent.ProcessTree.PID != 0 {
        ruleFailure.SetRuntimeProcessDetails(apitypes.ProcessTree{
            ProcessTree: enrichedEvent.ProcessTree,
            ContainerID: enrichedEvent.ContainerID,
        })
    }
    
    return ruleFailure
}
```

### 9. Configuration

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
    - "k8s_*"  # Ignore K8s-managed containers (already tracked as K8s)
  ignoreImages:
    - "pause:*"
```

### 10. Multiple Runtime Discovery with Fanotify

To monitor non-K8s containers started by Docker or other runtimes, we leverage inspektor-gadget's 
container-hook package which uses fanotify to watch OCI runtime binary executions.

#### Inspektor-Gadget's RuntimePaths

The `pkg/container-hook/runtime-finder` package provides a comprehensive list of OCI runtime paths:

```go
// From inspektor-gadget/pkg/container-hook/runtime-finder/finder.go

var RuntimePaths = []string{
    "/bin/runc",
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/usr/local/bin/runc",
    "/usr/local/sbin/runc",
    "/usr/lib/cri-o-runc/sbin/runc",
    "/usr/bin/crun",
    "/var/lib/rancher/k3s/data/current/bin/runc",    // k3s
    "/var/lib/rancher/rke2/bin/runc",                 // RKE2
    "/usr/libexec/crio/runc",                         // kubeadm/Debian, upstream crio
    "/var/lib/k0s/bin/runc",                          // k0s
    "/aarch64-bottlerocket-linux-gnu/sys-root/usr/bin/runc",  // Bottlerocket OS
    "/x86_64-bottlerocket-linux-gnu/sys-root/usr/bin/runc",   // Bottlerocket OS
    "/snap/microk8s/current/bin/runc",
}

// The tracer.go also adds conmon for CRI-O/Podman support:
var runtimePaths = append(RuntimePaths, "/usr/bin/conmon")
```

#### Using Inspektor-Gadget's Notify()

The `Notify()` function marks a runtime binary for fanotify monitoring:

```go
import (
    runtimefinder "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/runtime-finder"
    "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// Example usage from inspektor-gadget's tracer.go:
// notifiedPath, err := runtimefinder.Notify(runtimePath, host.HostRoot, runtimeBinaryNotify)

func (cw *ContainerWatcher) WatchAllRuntimes() error {
    // Initialize fanotify
    runtimeBinaryNotify, err := initFanotify()
    if err != nil {
        return err
    }
    
    runtimeFound := false
    
    // Check for custom runtime path via environment variable
    if runtimePath := os.Getenv("RUNTIME_PATH"); runtimePath != "" {
        notifiedPath, err := runtimefinder.Notify(runtimePath, host.HostRoot, runtimeBinaryNotify)
        if err != nil {
            return fmt.Errorf("notifying custom runtime %s: %w", runtimePath, err)
        }
        logger.L().Info("Monitoring custom runtime", helpers.String("path", notifiedPath))
        runtimeFound = true
    } else {
        // Try all known runtime paths
        for _, runtimePath := range runtimefinder.RuntimePaths {
            notifiedPath, err := runtimefinder.Notify(runtimePath, host.HostRoot, runtimeBinaryNotify)
            if err != nil {
                // Path doesn't exist or can't be watched, continue to next
                continue
            }
            logger.L().Debug("Monitoring runtime", 
                helpers.String("path", notifiedPath),
                helpers.String("original", runtimePath))
            runtimeFound = true
        }
        
        // Also watch conmon for CRI-O/Podman
        if notifiedPath, err := runtimefinder.Notify("/usr/bin/conmon", host.HostRoot, runtimeBinaryNotify); err == nil {
            logger.L().Debug("Monitoring conmon", helpers.String("path", notifiedPath))
            runtimeFound = true
        }
    }
    
    if !runtimeFound {
        return fmt.Errorf("no container runtime found in known paths: %v", runtimefinder.RuntimePaths)
    }
    
    return nil
}
```

#### Current Implementation: WithContainerFanotifyEbpf()

The existing `WithContainerFanotifyEbpf()` option in container-collection already handles this:

```go
// From container_watcher_collection.go
opts := []containercollection.ContainerCollectionOption{
    // ... other options ...
    
    // Get containers created with ebpf (works also if hostPid=false)
    containercollection.WithContainerFanotifyEbpf(),
    
    // ... other options ...
}
```

This option internally:
1. Uses fanotify with `FAN_OPEN_EXEC_PERM` to watch runc/crun execution
2. Uses eBPF on `sys_enter_execve` tracepoint to capture exec arguments
3. Parses OCI runtime command line to extract container bundle and pid file
4. Monitors pid file to detect container start and get container PID
5. Reads `config.json` from bundle directory for container metadata

#### How Container Context Detection Works

When a container is created via any runtime (K8s-managed or standalone Docker):

1. **Fanotify detects** runc/crun execution
2. **eBPF captures** command line arguments including `--bundle` and `--pid-file`
3. **Container-collection** parses OCI `config.json` to get container metadata
4. **Our callback** receives the container and determines context:
   - If `container.K8s.Namespace` and `container.K8s.PodName` are set → **K8s context**
   - If container has runtime info but no K8s info → **Docker context**
   - If mntns matches host mntns → **Host context**

```go
func (rm *RuleManager) determineContainerContext(container *containercollection.Container) EventSourceContext {
    // Host: no container ID or matches host mount namespace
    if container.Mntns == 0 || rm.mntnsRegistry.IsHost(container.Mntns) {
        return EventSourceHost
    }
    
    // K8s: has Kubernetes metadata (populated by K8s enrichment)
    if container.K8s.Namespace != "" && container.K8s.PodName != "" {
        return EventSourceK8s
    }
    
    // Docker/standalone: has container info but no K8s metadata
    return EventSourceDocker
}
```

#### Configuration for Additional Runtime Paths

If users have runtimes in non-standard paths, they can set the `RUNTIME_PATH` environment variable:

```yaml
# In node-agent deployment
env:
  - name: RUNTIME_PATH
    value: "/custom/path/to/runc"
```

Or we can add configuration support:

```go
// pkg/config/config.go

type Config struct {
    // ... existing fields ...
    
    // Additional OCI runtime paths to monitor (beyond inspektor-gadget defaults)
    AdditionalRuntimePaths []string `mapstructure:"additionalRuntimePaths"`
}
```

```yaml
# Example config
additionalRuntimePaths:
  - "/opt/custom-runtime/bin/runc"
  - "/home/user/.local/bin/crun"
```

## Event Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       eBPF Tracers (exec, open, network, etc.)          │
│    ┌─────────────────────────────────────────────────────────────┐      │
│    │  Events include: mntns_id, pid, comm, etc.                  │      │
│    └─────────────────────────────────────────────────────────────┘      │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Container Collection                              │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ ContainerCallback: Register containers by mntns                │     │
│  │   - K8s: has namespace + pod → register as K8s                 │     │
│  │   - No K8s info → register as Docker                           │     │
│  │   - mntns == host_mntns → register as Host                     │     │
│  └────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MntnsRegistry                                    │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  mntnsToContext: {                                             │     │
│  │    12345678 → K8s (namespace=default, pod=nginx)               │     │
│  │    87654321 → Docker (hostname=node1, container=redis)         │     │
│  │    11111111 → Host (hostname=node1)                            │     │
│  │  }                                                              │     │
│  └────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Event Handler Factory                                 │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  1. Receive raw event with mntns_id                            │     │
│  │  2. Lookup context from MntnsRegistry                          │     │
│  │  3. Create EnrichedEvent with SourceContext                    │     │
│  │  4. Dispatch to RuleManager                                    │     │
│  └────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Rule Manager                                    │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  ReportEnrichedEvent(event):                                   │     │
│  │    1. Check if context enabled (K8s/Host/Docker)               │     │
│  │    2. Get rules for context                                    │     │
│  │       - K8s: ListRulesForPod(namespace, pod)                   │     │
│  │       - Host/Docker: CreateAllRules() [simplified]             │     │
│  │    3. Skip profile-dependent rules for non-K8s                 │     │
│  │    4. Evaluate CEL expressions                                 │     │
│  │    5. Create context-aware RuleFailure                         │     │
│  │    6. Export alert                                             │     │
│  └────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Exporters                                      │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  RuleFailure with:                                             │     │
│  │    - AlertPlatform: "kubernetes" | "host" | "docker"           │     │
│  │    - RuntimeAlertK8sDetails (populated for K8s, minimal others)│     │
│  │    - HostDetails (for host events)                             │     │
│  │    - DockerDetails (for docker events)                         │     │
│  └────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Implementation Phases

### Phase 1: Core Infrastructure
1. Define `EventSourceContext` type and constants
2. Implement `MntnsRegistry` for mount namespace tracking
3. Add configuration options (`enableHostMonitoring`, `enableDockerMonitoring`)
4. Update container callbacks to detect and register container types
5. Host mount namespace detection at startup

### Phase 2: Rule Manager Updates
1. Update `EnrichedEvent` to carry source context and mount namespace
2. Implement context-aware event processing in `ReportEnrichedEvent`
3. Skip profile-dependent rules for non-K8s contexts
4. Add workload identifier logic for each context

### Phase 3: Alert Structure
1. Add `HostDetails` and `DockerDetails` to `GenericRuleFailure`
2. Add `SourceContext` field
3. Update `RuleFailureCreator` to populate context-specific details
4. Add new `AlertSourcePlatform` values
5. Update exporters to handle new alert types

### Phase 4: Multi-Runtime Discovery
1. Implement runtime socket discovery
2. Test with multiple container runtimes (Docker + containerd)
3. Document CRI socket configuration

### Phase 5: Testing & Integration
1. Unit tests for mntns registry
2. Unit tests for context detection
3. Integration tests with different container types
4. End-to-end tests for alerting
5. Documentation updates

## Migration Strategy

1. **Backward Compatibility**: Existing K8s monitoring unchanged
2. **Opt-in**: New features disabled by default
3. **Alert Format**: Option A (extended structure) maintains compatibility

## Future Considerations

1. **Application Profiles for Host/Docker**: Learning mode for non-K8s contexts
2. **Network Neighborhood for Docker**: Tracking container network behavior
3. **Rule Filtering for Docker**: Add container/image selectors to rule bindings
4. **Additional Contexts**: VMs, serverless functions, etc.
5. **CRI Socket Auto-Discovery**: More robust runtime detection