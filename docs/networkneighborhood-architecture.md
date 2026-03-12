# NetworkNeighborhood in node-agent: Architecture & Alert Flow

## Overview

The **NetworkNeighborhood (NN)** is a Kubernetes CRD that records the expected network communications (egress/ingress) for each container in a workload. Node-agent uses it in two modes:

1. **Auto-learning**: Node-agent observes network traffic via eBPF gadgets, builds the NN profile over time, and saves it to storage.
2. **User-defined**: A pre-created NN is loaded immediately from storage when a pod has the label `kubescape.io/user-defined-network: <nn-name>`. No learning phase occurs.

Once an NN exists (either mode), the **rule engine** evaluates runtime events against it. If a DNS query or network connection doesn't match the NN, an alert fires.

---

## 1. NetworkNeighborhood CRD Structure

**File**: `storage/pkg/apis/softwarecomposition/v1beta1/network_types.go`

```
NetworkNeighborhood
├── metadata (labels, annotations)
├── spec
│   ├── labelSelector          (pod selection criteria)
│   ├── containers[]           (one per container in the workload)
│   │   ├── name               (container name)
│   │   ├── ingress[]          (inbound traffic - NetworkNeighbor)
│   │   └── egress[]           (outbound traffic - NetworkNeighbor)
│   ├── initContainers[]
│   └── ephemeralContainers[]

NetworkNeighbor (single entry in egress/ingress)
├── identifier      (SHA256 hash of Type+IP+DNS+selectors)
├── type            ("internal" or "external")
├── dns             (deprecated single domain string)
├── dnsNames[]      (resolved domain names)
├── ports[]
│   ├── name        ("TCP-443")
│   ├── protocol    (TCP/UDP/SCTP)
│   └── port        (*int32)
├── podSelector     (for pod-to-pod traffic)
├── namespaceSelector (for cross-namespace traffic)
└── ipAddress       (raw IP for external traffic)
```

---

## 2. How NN Gets Loaded Into node-agent

### User-Defined Path (immediate, no learning)

**File**: `node-agent/pkg/objectcache/networkneighborhoodcache/networkneighborhoodcache.go`

When a container starts, `addContainer()` checks for a user-defined NN:

```
Container starts
  → containerwatcher detects EventTypeAddContainer
  → SetContainerInfo() reads pod label "kubescape.io/user-defined-network"
  → addContainer() in NN cache:
      if UserDefinedNetwork != "":
        1. Fetch full NN from storage by name
        2. Cache it in workloadIDToNetworkNeighborhood
        3. Set profileState = Full + Completed
        4. RETURN (skip learning entirely)
```

**Protection**: `workloadHasUserDefinedNetwork()` prevents periodic updates from overwriting user-defined NNs with auto-learned ones.

### Auto-Learned Path (progressive)

```
Container starts → learning phase begins
  → NetworkTracer (eBPF gadget) captures raw packets
  → ContainerProfileManager.ReportNetworkEvent() validates & stores
  → createNetworkNeighbor() converts to NetworkNeighbor:
      - Resolves pod/service selectors via K8s API
      - Performs DNS resolution for external IPs
      - Generates unique identifier hash
  → NN saved to storage periodically
  → NN cache fetches completed profiles on timer
```

---

## 3. How DNS Alerts Fire (R0005)

### Rule Definition

**File**: `node-agent/tests/chart/templates/node-agent/default-rules.yaml`

```yaml
- name: "DNS Anomalies in container"
  id: "R0005"
  expressions:
    ruleExpression:
      - eventType: "dns"
        expression: >
          !event.name.endsWith('.svc.cluster.local.')
          && !nn.is_domain_in_egress(event.containerId, event.name)
  profileDependency: 0   # runs regardless of profile existence
  severity: 1
```

**Logic**: Alert fires when a DNS query is NOT for a `.svc.cluster.local.` name AND the domain is NOT listed in the container's NN egress entries.

### Event Flow

```
1. trace_dns gadget (eBPF) captures DNS response packet
   File: node-agent/pkg/containerwatcher/v2/tracers/dns.go
   - Only processes DNS responses (not queries)
   - Only processes responses with answers (numAnswers > 0)

2. DNSTracer.callback() → eventCallback(event, containerID, processID)

3. EventHandlerFactory routes to RuleManager.ReportEnrichedEvent()
   File: node-agent/pkg/rulemanager/rule_manager.go

4. RuleManager evaluates:
   a. Gets rules for pod from RuleBindingCache
   b. Checks rule enabled + context tags + profile dependency
   c. Filters rule expressions for eventType="dns"
   d. Calls celEvaluator.EvaluateRule() with CEL expression

5. CEL evaluates nn.is_domain_in_egress(containerID, domain)
   File: node-agent/pkg/rulemanager/cel/libraries/networkneighborhood/network.go
   - Fetches NN for container from objectCache
   - Iterates egress[].dnsNames[] looking for the queried domain
   - Returns true if found (domain is whitelisted), false if not

6. If expression returns true (domain NOT in NN):
   → DnsAdapter creates RuleFailure with domain, IPs, process info
   → ExporterBus sends to all exporters (AlertManager, stdout, etc.)
   → AlertManager receives PostableAlert with labels:
       alertname=KubescapeRuleViolated, rule_id=R0005, domain=..., etc.
```

### nn.is_domain_in_egress Implementation

```go
// network.go:69-95
func (l *nnLibrary) isDomainInEgress(containerID, domain ref.Val) ref.Val {
    container, err := profilehelper.GetContainerNetworkNeighborhood(l.objectCache, containerIDStr)
    if err != nil {
        return cache.NewProfileNotAvailableErr(...)  // NN not loaded yet
    }
    for _, egress := range container.Egress {
        if slices.Contains(egress.DNSNames, domainStr) || egress.DNS == domainStr {
            return types.Bool(true)  // domain whitelisted
        }
    }
    return types.Bool(false)  // domain NOT in NN → alert
}
```

---

## 4. Other NN-Based CEL Functions

All defined in `node-agent/pkg/rulemanager/cel/libraries/networkneighborhood/nn.go`:

| Function | Args | Purpose |
|----------|------|---------|
| `nn.is_domain_in_egress(containerID, domain)` | string, string | DNS name in egress? |
| `nn.is_domain_in_ingress(containerID, domain)` | string, string | DNS name in ingress? |
| `nn.was_address_in_egress(containerID, address)` | string, string | IP in egress? |
| `nn.was_address_in_ingress(containerID, address)` | string, string | IP in ingress? |
| `nn.was_address_port_protocol_in_egress(containerID, addr, port, proto)` | string, string, int, string | IP+port+proto in egress? |
| `nn.was_address_port_protocol_in_ingress(containerID, addr, port, proto)` | string, string, int, string | IP+port+proto in ingress? |

---

## 5. GeneratedNetworkPolicy: From NN to K8s Enforcement

**File**: `storage/pkg/apis/softwarecomposition/networkpolicy/v2/networkpolicy.go`

The storage API can convert an NN into a standard K8s `NetworkPolicy` on-the-fly:

```
NN (in storage) → GenerateNetworkPolicy() → GeneratedNetworkPolicy CRD
```

### Availability Check (IsAvailable)

For policy generation to work, the NN must have ONE of:
- Annotation `kubescape.io/managed-by: User`
- Annotation `kubescape.io/status: completed` or `learning`

### Conversion Logic

```
For each egress NetworkNeighbor:
  - If PodSelector set → NetworkPolicyPeer with podSelector
  - If NamespaceSelector set → attached to pod peer
  - If IPAddress set → NetworkPolicyPeer with ipBlock (CIDR /32)
  - Ports → NetworkPolicyPort entries

Rules are deduplicated by SHA256 hash.
Rules sharing the same ports are merged (combining IPBlocks).
```

### Applying the Policy

The GeneratedNetworkPolicy is a **read-only CRD** in storage. To enforce it:
1. GET from storage API: `storageClient.GeneratedNetworkPolicies(ns).Get(name)`
2. Convert to K8s `networking/v1.NetworkPolicy` (JSON marshal/unmarshal)
3. CREATE via K8s API: `kubeClient.NetworkingV1().NetworkPolicies(ns).Create(policy)`

**Requires a CNI that supports NetworkPolicy** (Calico, Cilium, etc.). KindNET does NOT enforce policies.

---

## 6. Alert Flow: From Rule Failure to AlertManager

**File**: `node-agent/pkg/exporters/alert_manager.go`

```
RuleManager creates RuleFailure
  → ExporterBus.SendRuleAlert() dispatches to all exporters
  → AlertManagerExporter:
      1. Builds PostableAlert with:
         - Labels: alertname, rule_name, rule_id, namespace, pod_name,
                   container_name, severity, pid, comm, etc.
         - Annotations: title (summary), description (rule desc), fix suggestion
         - StartsAt/EndsAt: now → now+1h
      2. POSTs to AlertManager API: POST /api/v2/alerts
```

### Cooldown Mechanism

Before sending, `ruleCooldown.ShouldCooldown(uniqueID, containerID, ruleID)` prevents duplicate alerts. The `uniqueID` is a CEL expression result, e.g., for R0005: `event.comm + '_' + event.name` (process name + domain).

---

## 7. Detection Rules Reference

### Rules That Use NetworkNeighborhood

| Rule | ID | eventType | Expression | profileDependency |
|------|----|-----------|------------|-------------------|
| DNS Anomalies | R0005 | dns | `!event.name.endsWith('.svc.cluster.local.') && !nn.is_domain_in_egress(...)` | 0 (NotRequired) |

### Rules That Use ApplicationProfile (for comparison)

| Rule | ID | eventType | Expression |
|------|----|-----------|------------|
| Unexpected process | R0001 | exec | `!ap.was_executed(event.containerId, event.path, event.args)` |
| Unexpected file access | R0002 | open | `!ap.was_path_opened(event.containerId, event.path)` |
| Unexpected capability | R0003 | capabilities | `!ap.was_capability_used(...)` |
| Unexpected syscall | R0007 | syscall | `!ap.was_syscall_called(...)` |

### profileDependency Values

| Value | Meaning | Behavior |
|-------|---------|----------|
| 0 | NotRequired | Rule runs even without a profile |
| 1 | Optional | Rule runs but may have reduced accuracy without profile |
| 2 | Required | Rule skipped if no ApplicationProfile exists |

---

## 8. Key Labels and Annotations

### Pod Labels (set by user on Deployments)

| Label | Purpose |
|-------|---------|
| `kubescape.io/user-defined-network: <nn-name>` | Links pod to a pre-created NetworkNeighborhood |
| `kubescape.io/user-defined-profile: <ap-name>` | Links pod to a pre-created ApplicationProfile |

### NN Annotations (set on the NetworkNeighborhood object)

| Annotation | Purpose |
|------------|---------|
| `kubescape.io/managed-by: User` | Marks NN as user-managed (enables GeneratedNetworkPolicy) |
| `kubescape.io/status: completed` | Marks NN learning as complete |

### NN Labels (needed for GenerateNetworkPolicy)

| Label | Purpose |
|-------|---------|
| `kubescape.io/workload-kind: Deployment` | Used to generate policy name |
| `kubescape.io/workload-name: my-deploy` | Used to generate policy name |

---

## 9. End-to-End: User-Defined NN Detection Flow

```
PRE-REQUISITES:
  1. Create NetworkNeighborhood CRD with:
     - Egress entries listing allowed domains (dnsNames) and IPs
     - Annotation: kubescape.io/managed-by: User
     - Labels: kubescape.io/workload-kind, kubescape.io/workload-name
  2. Create Deployment with pod label:
     kubescape.io/user-defined-network: <nn-name>
  3. (Optional) Create ApplicationProfile for exec detection
     with pod label: kubescape.io/user-defined-profile: <ap-name>

RUNTIME:
  Pod starts → node-agent detects container
    → Reads "kubescape.io/user-defined-network" label
    → Fetches NN from storage, caches as Completed
    → trace_dns gadget runs, captures DNS responses

  Container resolves "evil.example.com":
    → trace_dns captures response → DNSEvent
    → RuleManager evaluates R0005:
       CEL: !nn.is_domain_in_egress(containerID, "evil.example.com")
       → NN egress has ["fusioncore.ai", "cluster-dns"] but NOT "evil.example.com"
       → Expression returns true → ALERT
    → AlertManager receives: rule_id=R0005, domain=evil.example.com, pod=...

ENFORCEMENT (optional, separate from detection):
  Query GeneratedNetworkPolicy from storage API
    → Convert to K8s NetworkPolicy
    → Apply to cluster (requires Calico/Cilium CNI)
    → Cluster blocks traffic to IPs not in policy
```
