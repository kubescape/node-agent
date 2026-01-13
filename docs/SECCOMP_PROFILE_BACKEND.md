# SeccompProfile Storage Backend

This document describes the configurable storage backend for SeccompProfile resources, allowing installations to choose between the aggregated API server storage or native Kubernetes CRDs.

## Overview

SeccompProfile resources can be stored in two different backends:

| Backend | API Group | Storage | Use Case |
|---------|-----------|---------|----------|
| `crd` (default) | `kubescape.io/v1` | Native Kubernetes CRD (etcd) | Standard installations |
| `storage` | `spdx.softwarecomposition.kubescape.io/v1beta1` | Aggregated API Server (file-based) | Legacy installations |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Helm Installation                                │
│                  seccompProfileBackend: ?                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│    Backend: "crd"       │     │   Backend: "storage"    │
│    (default)            │     │                         │
├─────────────────────────┤     ├─────────────────────────┤
│ API Group:              │     │ API Group:              │
│ kubescape.io            │     │ spdx.softwarecomposi... │
│                         │     │                         │
│ Storage:                │     │ Storage:                │
│ Native CRD (etcd)       │     │ Aggregated API Server   │
│                         │     │ (file-based backend)    │
└─────────────────────────┘     └─────────────────────────┘
              │                               │
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│  CRDSeccompClient       │     │  StorageSeccompClient   │
│  (dynamic client)       │     │  (typed storage client) │
└─────────────────────────┘     └─────────────────────────┘
              └───────────────┬───────────────┘
                              ▼
              ┌───────────────────────────────┐
              │    SeccompProfileClient       │
              │    (interface)                │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   SeccompProfileWatcher       │
              │   (backend-agnostic)          │
              └───────────────────────────────┘
```

## Why Different API Groups?

The storage component registers an **APIService** for the entire `spdx.softwarecomposition.kubescape.io/v1beta1` group. This means all requests to that API group are routed to the aggregated API server.

If we created a CRD in the same group:
1. The APIService takes precedence over CRDs
2. All requests would still go to the aggregated API server
3. The CRD would be effectively "shadowed"

By using `kubescape.io/v1` for the CRD:
- No APIService claims this group
- The CRD is served directly by the Kubernetes API server
- No conflict with the storage component

## Configuration

### Helm Values

```yaml
capabilities:
  seccompProfileService: enable
  seccompProfileBackend: crd  # "crd" (default) or "storage"
```

### Node-Agent Configuration

The node-agent config receives the backend setting:

```json
{
  "seccompServiceEnabled": true,
  "seccompProfileBackend": "crd"
}
```

## Component Behavior

### Storage Component

When `seccompProfileBackend: crd`:
- Sets `disableSeccompProfileEndpoint: true` in config
- Does NOT register the `seccompprofiles` REST endpoint
- Other resources (applicationprofiles, vulnerabilitymanifests, etc.) are unaffected

When `seccompProfileBackend: storage` (default):
- Registers `seccompprofiles` endpoint as normal
- Stores SeccompProfiles in file-based storage

### Node-Agent

The `SeccompProfileWatcher` is backend-agnostic, using the `SeccompProfileClient` interface:

```go
// SeccompProfileClient interface abstracts the backend
type SeccompProfileClient interface {
    WatchSeccompProfiles(namespace string, opts metav1.ListOptions) (watch.Interface, error)
    ListSeccompProfiles(namespace string, opts metav1.ListOptions) (*v1beta1.SeccompProfileList, error)
    GetSeccompProfile(namespace, name string) (*v1beta1.SeccompProfile, error)
}

// Factory creates the appropriate implementation based on config
seccompClient := storage.CreateSeccompProfileClient(
    cfg.SeccompProfileBackend,
    storageClient.GetStorageClient(),
    k8sClient.GetDynamicClient(),
)

// Watcher uses the interface - doesn't know which backend is used
seccompWatcher := seccompprofilewatcher.NewSeccompProfileWatcher(seccompClient, seccompManager)
```

Two implementations of `SeccompProfileClient` exist:
- `StorageSeccompProfileClient`: Uses the typed storage client for `spdx.softwarecomposition.kubescape.io/v1beta1`
- `CRDSeccompProfileClient`: Uses the dynamic client for `kubescape.io/v1`, converting unstructured objects internally

### Synchronizer

When `manageWorkloads` is enabled, the synchronizer is responsible for **creating** SeccompProfile resources. The synchronizer:

1. Receives SeccompProfile definitions from the ARMO cloud backend
2. Creates/updates SeccompProfile resources in the cluster using the appropriate API group based on the backend configuration
3. In CRD mode, writes to `kubescape.io/v1` SeccompProfiles
4. In storage mode, writes to `spdx.softwarecomposition.kubescape.io/v1beta1` SeccompProfiles

**Note:** When the storage endpoint is disabled (`seccompProfileBackend: crd`), the synchronizer must be configured to write to the CRD backend. The synchronizer's ConfigMap automatically uses the correct API group based on the `seccompProfileBackend` setting.

## RBAC

ClusterRoles are dynamically configured based on the backend:

**Storage mode:**
```yaml
- apiGroups: ["spdx.softwarecomposition.kubescape.io"]
  resources: ["seccompprofiles"]
  verbs: ["get", "watch", "list"]
```

**CRD mode:**
```yaml
- apiGroups: ["kubescape.io"]
  resources: ["seccompprofiles"]
  verbs: ["get", "watch", "list"]
```

## Migration

### What Happens When Switching Backends?

**There is no automatic migration between backends.** The two backends use different API groups (`spdx.softwarecomposition.kubescape.io` vs `kubescape.io`), so they are completely separate resources in Kubernetes.

When switching from `storage` to `crd`:
1. Existing SeccompProfiles in the storage backend remain but are no longer accessible via the storage API (since the endpoint is disabled)
2. The node-agent will start watching the new CRD backend (empty initially)
3. The synchronizer will create new SeccompProfiles in the CRD backend
4. Old storage-based profiles are orphaned and should be manually deleted

When switching from `crd` to `storage`:
1. Existing CRD-based SeccompProfiles remain in etcd
2. The node-agent will start watching the storage backend
3. The synchronizer will create new SeccompProfiles in the storage backend
4. Old CRD-based profiles are orphaned and should be manually deleted

### Migration Steps

To migrate existing SeccompProfiles:

1. **Export existing profiles** (before switching):
   ```bash
   # For storage backend
   kubectl get seccompprofiles.spdx.softwarecomposition.kubescape.io -A -o yaml > profiles-backup.yaml

   # For CRD backend
   kubectl get seccompprofiles.kubescape.io -A -o yaml > profiles-backup.yaml
   ```

2. **Update Helm values** and upgrade the release

3. **Trigger re-sync** from the cloud backend (if using synchronizer), or manually recreate profiles

4. **Clean up orphaned profiles**:
   ```bash
   # Delete old storage profiles (after switching to CRD)
   kubectl delete seccompprofiles.spdx.softwarecomposition.kubescape.io -A --all

   # Delete old CRD profiles (after switching to storage)
   kubectl delete seccompprofiles.kubescape.io -A --all
   ```

### Recommended Approach

For most installations, **avoid switching backends after initial deployment**. Choose the appropriate backend during initial installation based on your requirements.

## Files Modified

| Component | File | Change |
|-----------|------|--------|
| Helm | `values.yaml` | Added `seccompProfileBackend` |
| Helm | `templates/storage/seccompprofile-crd.yaml` | CRD definition (conditional) |
| Helm | `templates/storage/configmap.yaml` | Passes `disableSeccompProfileEndpoint` |
| Helm | `templates/node-agent/configmap.yaml` | Passes `seccompProfileBackend` |
| Helm | `templates/node-agent/clusterrole.yaml` | Conditional API group |
| Helm | `templates/synchronizer/clusterrole.yaml` | Conditional API group |
| Helm | `templates/synchronizer/configmap.yaml` | Conditional API group |
| Storage | `pkg/config/config.go` | Added `DisableSeccompProfileEndpoint` |
| Storage | `pkg/apiserver/apiserver.go` | Conditional endpoint registration |
| Node-Agent | `pkg/config/config.go` | Added `SeccompProfileBackend` |
| Node-Agent | `pkg/storage/storage_interface.go` | `SeccompProfileClient` interface |
| Node-Agent | `pkg/storage/v1/seccompprofile.go` | Storage backend implementation |
| Node-Agent | `pkg/storage/v1/seccompprofile_crd.go` | CRD backend implementation |
| Node-Agent | `pkg/storage/v1/storage.go` | Factory function |
| Node-Agent | `pkg/watcher/seccompprofilewatcher/` | Backend-agnostic watcher |
| Node-Agent | `cmd/main.go` | Uses `SeccompProfileClient` factory |
