# Host Monitoring Completion

Before this change, enabling `HostMonitoringEnabled` (`pkg/config/config.go`) got you a virtual "host" pseudo-container (`pkg/containerwatcher/v2/container_watcher_collection.go`) with two working pipelines — rule/alert evaluation and network-stream mapping — and three broken ones: application-profile generation silently stalled, SBOM generation was an explicit no-op, and malware detection was an explicit no-op. This document describes how all three were unblocked, and the one genuine bug found along the way.

## Why profile and SBOM needed different fixes

Profile generation and malware detection share a single root cause: both wait on `k8sObjectCache.GetSharedContainerData`, which returns `nil` for host because nothing ever populates it — there is no real Kubernetes pod backing the host pseudo-container. SBOM generation does not share that root cause at all: the container SBOM path is driven entirely by image/mount data (`ContainerImageName`, `getMountedVolumes`, `imageStatus`) that a host simply doesn't have, regardless of shared-container-data. Treating all three as "one fix" (an earlier draft of this work did) doesn't survive contact with the code — SBOM needed its own, wholly separate scan branch.

## The shared host-identity builder (`pkg/hostidentity`)

`pkg/hostidentity` resolves a stable per-node identity and builds the synthetic, K8s-shaped values that profile and malware detection need:

| Function | Purpose |
|---|---|
| `ResolveHostID(cfg *config.Config) (string, error)` | Primary source is `cfg.NodeName` (populated from the `NODE_NAME` downward-API env var — stable across restarts). Falls back to `$HOST_ROOT/etc/machine-id` only if `NodeName` is empty. Returns an error rather than silently returning `""` — a caller getting an empty identity string is worse than a caller handling an error. |
| `BuildHostWlid(hostID)` | `wlid://cluster-unknown/namespace-host/host-<hostID>` |
| `BuildHostInstanceID(hostID)` | A real `instanceidhandler.IInstanceID` (not a string) with `InstanceType`/`TemplateHash` set explicitly, since both surface via `GetLabels()`. |
| `BuildHostWatchedContainerData(hostID)` | A `WatchedContainerData` with every field explicit — `ContainerID="host"`, `Namespace="host"`, `ContainerType=containers` (there is no dedicated `Host` enum value), `PreRunningContainer=false`, `UserDefinedProfile=""` (this is a **string** field, not `bool`), and a single-entry `ContainerInfos` map (see "the ContainerInfos crash" below). |

This package lives outside `pkg/utils` deliberately: `pkg/utils` is imported by `pkg/objectcache`, which `WatchedContainerData` itself lives in, so placing the builder in `pkg/utils` would create an import cycle.

`pkg/hostsensormanager.HostFSPrefix()` was exported (it was previously the unexported `hostFSPrefix`, sourced from the `HOST_ROOT` env var) so both this package and the SBOM host branch can read the same host-filesystem-mount convention without re-deriving it.

## Single injection point

`pkg/containerwatcher/v2/containercallback.go` used to skip shared-data setup for host entirely. It now branches explicitly: `utils.IsHostContainer(...)` routes through the `hostidentity` builder and `k8sObjectCache.SetSharedContainerData("host", ...)`; everything else is unchanged. This is deliberately a **replacement**, not a deletion of the skip — falling through to the real-container path would call `k8sClient.GetWorkload("", "")` for a workload that will never exist, retried on an unbounded exponential backoff, leaking a goroutine per node forever.

## Consumer audit

Once `GetSharedContainerData("host")` stopped returning `nil`, every consumer that assumed non-nil implies "this is backed by a real Kubernetes object" needed a look — a well-formed-but-fake K8s lookup result is worse in a security agent than a loud, obvious skip. Sites audited:

| Site | Disposition |
|---|---|
| `pkg/rulemanager/profilehelper/profilehelper.go` (`GetPodSpec`) | **Guarded.** Host returns an empty `PodSpec` instead of attempting a live lookup that would always miss. |
| `pkg/rulemanager/ruleadapters/creator.go` (`setRuntimeAlertK8sDetails`, PodUID/WorkloadUID) | **Guarded.** This is a separate function from the presence-based check in `setProfileMetadata` — it was not already covered. |
| `pkg/containerprofilemanager/v1/lifecycle.go` (shared-data read) | **Already safe** — pure cache read, no K8s-specific sub-call. What changed is that it now *succeeds* instead of spinning to the wait deadline. |
| `pkg/rulemanager/containercallbacks.go` | **Already safe** — `rule_manager.go`'s pre-existing `IsHostContainer` bypass means this is never reached for host. |
| `pkg/networkstream/v1/network_stream.go` | **Unchanged, verified by regression test** — its existing host handling doesn't rely on shared data being `nil`. |
| `pkg/objectcache/containerprofilecache/containerprofilecache.go` | **The site that was stalling.** Now proceeds and reaches storage; covered by an end-to-end test. |
| `pkg/sbommanager/v1/sbom_manager.go` | **Unreachable for host** — host now short-circuits into its own branch (see below) before this point is ever reached. |

The dead scaffolding fields `hostProfile`/`hostProfileMu`/`hostID` in `containerprofile_manager.go` were deleted — nothing in the repo referenced them.

**No change to the alert payload.** `creator.go`'s `setProfileMetadata` used to check `if state != nil` before attaching `ProfileMetadata` — but `GetContainerProfileState` never actually returns `nil` (it synthesizes an error state when profile data is absent), so that check was dead code, and every alert got a `ProfileMetadata{Type, ProfileDependency, Error}` regardless of whether a profile actually existed. An earlier draft of this fix replaced that dead check with `state.Error == nil`, which turned out to be a real (if narrow) regression: it withheld `ProfileMetadata` entirely — including the `Error` field — whenever a profile was absent, for host and real containers alike. The final version instead always attaches `ProfileMetadata` (as the code always effectively did, since the old check never actually filtered anything) and continues to surface `state.Error` via the `Error` field when present — restoring the original behavior for real containers while extending it correctly to host.

## The ContainerInfos crash

A test that drove real exec/open/syscall/capability events through the host profile pipeline and asserted the resulting CR actually contained that data (not just an empty shell) caught a real bug: `hostidentity`'s synthetic `WatchedContainerData` didn't set `ContainerInfos`, and `monitoring.go`'s `saveContainerProfile` unconditionally indexes `ContainerInfos[ContainerType][ContainerIndex]` when building the CR. Host's first successful save would have panicked. Fixed by giving the synthetic data a single-entry `ContainerInfos` map.

## Profile finalization

`calculateSniffingTime`/`handleContainerMaxTime` (`pkg/containerprofilemanager/v1/lifecycle.go`) apply a fixed `MaxSniffingTime` timer to every container and delete the entry when it fires — correct for a bounded container lifetime, wrong for an always-on host. `EnableRuntimeDetection`/`EnablePartialProfileGeneration` were investigated as a possible mitigation and confirmed **not** to help: they only gate pre-running-container admission, and are never read by the finalization timer. The fix is a direct bypass: the timer is simply never armed for the host pseudo-container (mirroring the existing `IsHostContainer`-bypass convention used elsewhere, e.g. `rule_manager.go`), leaving real-container finalization completely unchanged.

**Consequence:** `ContainerReachedMaxTime` (`monitoring.go`) is the only normal path to `WatchedContainerStatusCompleted`, and it is never sent for host. This means the host profile never reaches `Completed`, and `creator.go`'s `FailOnProfile: state.Status == helpersv1.Completed` is therefore permanently `false` on every host alert — host alerts are always stamped as if the profile were still learning, even once it has meaningfully converged. This is the accepted trade-off for continuous learning on an always-on entity (the alternative, finalizing and deleting the host profile, is strictly worse); it is not a bug, but operators consuming `FailOnProfile` on host alerts should be aware it carries no signal for host the way it does for containers.

## SBOM: a separate scan branch

`pkg/sbommanager/v1/host_sbom.go` is a standalone branch — it never touches `k8sObjectCache`/`SetSharedContainerData`, and never calls into the image/mount-driven `awaitAndSubmit` machinery the container path uses.

**Scan source.** `pkg/sbommanager/v1/syftutil/directory_source.go` adds a Syft directory-source construction (`directorysource.New`) pointed at `HostFSPrefix()`'s path, with an explicit `Exclude` list so the scan doesn't ingest every container image layer on the node:

```
./var/lib/containerd/**  ./var/lib/docker/**  ./var/lib/containers/**  ./var/lib/rancher/**
./run/containerd/**      ./run/docker/**      ./run/crio/**
./proc/**  ./sys/**  ./dev/**
```

Two non-obvious Syft API details, pinned by tests:
- Exclusion patterns must be **scan-root-relative**, starting with `./`, `*/`, or `**/` — an absolute pattern like `/var/lib/containerd/**` is rejected outright by `directorysource.GetDirectoryExclusionFunctions`.
- That same function **mutates the exclusion slice in place** (prefixing each entry with the root). The host scan clones the exclusion list before each use so a second scan doesn't get double-prefixed patterns.

**Cadence.** One scan at host registration, plus a periodic re-scan on `HostSBOMRescanInterval` (new config field, default 24h — containers have no periodic re-scan at all, only event-triggered reprocessing on a scanner-version bump, so this is genuinely new, host-only behavior). The host scan loop runs on its own goroutine, not the shared container-SBOM worker pool, so a full host-root walk can't head-of-line-block container SBOM generation.

**Interaction with the `TooLarge` state machine.** A `TooLarge` trip blocks only the current rescan attempt, not future ones — it's released the same way the container path's are (a Syft tool-version bump or a scanner-memory-limit change). A permanent block would mean a node could never recover after a config change; an unconditional retry would burn a full root-filesystem walk every interval only to have the result dropped by storage's one-way-door write guard.

**Naming and failure reporting.** The `SBOMSyft` CR is named/labeled from `hostidentity.ResolveHostID`, not image-derived fields. `reportFailure` (the kubevuln-facing scan-failure report, keyed by `ImageTag`/`ImageHash`/pod `WorkloadIdentifier`) is explicitly skipped for host via a documented no-op — none of those fields exist for a host scan.

**Scan timeout.** The Syft scan runs under a 16-minute `context.WithTimeout` (matching the container path's sidecar-scan bound) rather than the bare manager-lifetime context — a host-root walk hung on a slow mount is bounded, not indefinite. A timeout reports a distinct `"timeout"` metric outcome (alongside the existing `"success"`/`"error"`) and falls through the same failure handling as any other scan error, which unconditionally clears the in-flight `processing` marker — so a timed-out scan is recoverable on the next rescan tick, not a permanent stall.

## Vulnerability scanning stays external

node-agent never performs vulnerability scanning (CVE matching) for containers or the host — it only produces `SBOMSyft` CRs. `kubevuln` is a fully separate, externally-deployed component that consumes those CRs; it needed no changes here. No `SBOMSyftFiltered` or relevancy-filtering mechanism exists in this repo — `containerprofilecache`'s `projection_compile.go`/`reconciler.go` are unrelated rule-engine runtime-projection code (opens/execs/syscalls for the CEL rule engine), not SBOM filtering.

## Malware detection

`pkg/malwaremanager/v1/malware_manager.go` removed the `IsHostContainer` exclusion that previously dropped host before any tracking began, and added an explicit host bypass for the separate `IgnoreContainer` check immediately after it (host must not be dropped by ignore-list logic meant for real containers, e.g. namespace-based rules that could accidentally match an empty/host namespace). `reportFileExec`/`reportFileOpen` needed no changes — they key only on `containerID` against maps populated by the callback change, with no profile or K8s-specific branching.

## What is still out of scope

- Manual/live-cluster verification (`kubectl get sbomsyft`/`containerprofile` against a real host, observing live malware/alert events) was not performed — no live cluster is available in the environment this work was done in. The automated tests described above substitute for it: end-to-end profile-content population, real-Syft-scan exclusion fixtures, and Wlid-enrichment assertions on real malware events.
- Noise reduction / allowlisting for host-level malware and profile alerting (legitimate system daemons look different from container workloads) is a follow-up, not addressed here.
