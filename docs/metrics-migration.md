# Metrics Migration Guide: Prometheus → OTEL SDK

This document maps every old Prometheus metric name to its new OTEL SDK name.
Required for Phase 2 merge per the instrumentation plan (AC7).

## Background

Phase 2 replaces `pkg/metricsmanager/prometheus/` with `pkg/metricsmanager/otel/`.
Metric names change from legacy Prometheus conventions (`_counter` suffix, flat names)
to OTEL semantic conventions (dot-separated namespaces). When
`OTEL_METRICS_EXPORTER=prometheus` the OTEL→Prometheus bridge converts `.` → `_`,
so `node_agent.ebpf.exec.total` is exposed as `node_agent_ebpf_exec_total`.

**This is a breaking rename.** Existing Prometheus dashboards and alerting rules that
reference the old names must be updated. See the mapping table below.

## Metric Name Mapping

### eBPF Event Counters (17 → 1)

The 17 individual per-event-type counters are collapsed into one counter with an
`event_type` label. This eliminates metric proliferation and adds coverage for
previously missing event types (`exit`, `fork`).

| Old Prometheus name | New OTEL name (Prometheus: `_` replaces `.`) | Label change |
|---|---|---|
| `node_agent_exec_counter` | `node_agent_ebpf_events_total{event_type="execve"}` | new `event_type` label |
| `node_agent_open_counter` | `node_agent_ebpf_events_total{event_type="open"}` | new `event_type` label |
| `node_agent_network_counter` | `node_agent_ebpf_events_total{event_type="network"}` | new `event_type` label |
| `node_agent_dns_counter` | `node_agent_ebpf_events_total{event_type="dns"}` | new `event_type` label |
| `node_agent_syscall_counter` | `node_agent_ebpf_events_total{event_type="syscall"}` | new `event_type` label |
| `node_agent_capability_counter` | `node_agent_ebpf_events_total{event_type="capabilities"}` | new `event_type` label |
| `node_agent_randomx_counter` | `node_agent_ebpf_events_total{event_type="randomx"}` | new `event_type` label |
| `node_agent_symlink_counter` | `node_agent_ebpf_events_total{event_type="symlink"}` | new `event_type` label |
| `node_agent_hardlink_counter` | `node_agent_ebpf_events_total{event_type="hardlink"}` | new `event_type` label |
| `node_agent_ssh_counter` | `node_agent_ebpf_events_total{event_type="ssh"}` | new `event_type` label |
| `node_agent_http_counter` | `node_agent_ebpf_events_total{event_type="http"}` | new `event_type` label |
| `node_agent_ptrace_counter` | `node_agent_ebpf_events_total{event_type="ptrace"}` | new `event_type` label |
| `node_agent_iouring_counter` | `node_agent_ebpf_events_total{event_type="iouring"}` | new `event_type` label |
| `node_agent_kmod_counter` | `node_agent_ebpf_events_total{event_type="kmod"}` | new `event_type` label |
| `node_agent_unshare_counter` | `node_agent_ebpf_events_total{event_type="unshare"}` | new `event_type` label |
| `node_agent_bpf_counter` | `node_agent_ebpf_events_total{event_type="bpf"}` | new `event_type` label |
| `node_agent_ebpf_event_failure_counter` | `node_agent_ebpf_events_failed_total` | no label |

### Rule Metrics

| Old Prometheus name | New OTEL name | Label change |
|---|---|---|
| `node_agent_rule_counter{rule_id}` | `node_agent_rule_processed_total{rule_id}` | `rule_id` now uses `rule.ID` (stable ID) instead of `rule.Name` |
| `node_agent_rule_prefiltered_total{rule_id}` | `node_agent_rule_prefiltered_total{rule_id}` | `rule_id` now uses `rule.ID` |
| `node_agent_alert_counter{rule_id}` | `node_agent_alert_total{rule_id}` | `rule_id` now uses `rule.ID` |
| `node_agent_rule_evaluation_time_seconds{rule_id,event_type}` | `node_agent_rule_evaluation_duration{rule_id,event_type}` | `rule_id` now uses `rule.ID`; bucket boundaries updated |

**Note:** `rule_id` label values change from rule display names to stable rule IDs
(e.g. `R1001` instead of `Unexpected process launched`). Update alert queries accordingly.

### Container Metrics

| Old Prometheus name | New OTEL name |
|---|---|
| `node_agent_container_start_counter` | `node_agent_container_start_total` |
| `node_agent_container_stop_counter` | `node_agent_container_stop_total` |
| `node_agent_dedup_events_total{event_type,result}` | `node_agent_ebpf_dedup_total{event_type,result}` |

### ContainerProfile Cache Metrics

| Old Prometheus name | New OTEL name |
|---|---|
| `node_agent_user_profile_legacy_loads_total{kind,completeness}` | `node_agent_profile_legacy_load_total{kind,completeness}` |
| `node_agent_containerprofile_cache_entries{kind}` | `node_agent_profile_cache_entries{kind}` |
| `node_agent_containerprofile_cache_hit_total{result}` | `node_agent_profile_cache_hit_total{result}` |
| `node_agent_containerprofile_reconciler_duration_seconds{phase}` | `node_agent_profile_reconciler_duration{phase}` |
| `node_agent_containerprofile_reconciler_evictions_total{reason}` | `node_agent_profile_reconciler_evictions_total{reason}` |

### Rule Projection Metrics

| Old Prometheus name | New OTEL name |
|---|---|
| `rule_load_rejected_missing_declaration_total{rule_id}` | `node_agent_rule_projection_missing_decl_total{rule_id}` |
| `rule_projection_undeclared_literal_total{helper}` | `node_agent_rule_projection_undeclared_literal_total{helper}` |
| `rule_projection_stale_entries` | `node_agent_rule_projection_stale_entries` |
| `rule_projection_undeclared_rules` | `node_agent_rule_projection_undeclared_rules` |
| `rule_projection_spec_compile_total` | `node_agent_rule_projection_spec_compile_total` |
| `rule_projection_spec_hash_changes_total` | `node_agent_rule_projection_spec_hash_change_total` |
| `rule_projection_spec_patterns{field,kind}` | `node_agent_rule_projection_spec_patterns{field,kind}` |
| `rule_projection_spec_all_fields{field}` | `node_agent_rule_projection_spec_all_field{field}` |
| `rule_projection_apply_duration_seconds` | `node_agent_rule_projection_apply_duration` |
| `rule_projection_reconcile_triggered_total{trigger}` | `node_agent_rule_projection_reconcile_triggered_total{trigger}` |
| `rule_helper_call_total{helper}` | `node_agent_rule_projection_helper_call_total{helper}` |
| `rule_projection_undeclared_rules_list{rule_id}` | `node_agent_rule_projection_undeclared_rules_detail{rule_id}` |

### Memory-Savings Metrics (dev-only)

| Old Prometheus name | New OTEL name |
|---|---|
| `profile_raw_size_bytes` | `node_agent_profile_raw_size` |
| `profile_projected_size_bytes` | `node_agent_profile_projected_size` |
| `profile_entries_raw_total{field}` | `node_agent_profile_entries_raw{field}` |
| `profile_entries_retained_total{field}` | `node_agent_profile_entries_retained{field}` |
| `profile_retention_ratio{field}` | `node_agent_profile_retention_ratio{field}` |

### New Metrics (no old equivalent)

| New OTEL name | Description |
|---|---|
| `node_agent_ebpf_events_dropped_total{reason}` | eBPF events dropped due to backpressure (`reason=worker_channel_full`) or profile drops |
| `node_agent_pod_memory_cgroup_bytes` | Pod-level memory usage, read from the parent `kubepods-*-pod<UID>.slice` cgroup (one level above the container `.scope`). Covers every container in the pod, including third-party sidecars with no OTEL instrumentation of their own (e.g. `clamav`, gated behind `capabilities.malwareDetection`). Additive alongside `node_agent_process_memory_cgroup_bytes`, which stays container-scoped and unchanged. |
| `node_agent_pod_memory_cgroup_limit_bytes` | Pod-level memory limit, paired with `node_agent_pod_memory_cgroup_bytes` (0 = unlimited/unresolved). |

### Cgroup Scope Resolution Hardening (accuracy fix, no name change)

`node_agent_process_memory_cgroup_bytes` / `..._cgroup_limit_bytes` (and the new pod-level
metrics above) are read via `findCgroupScopeDir` / `resolveCgroupMemoryPaths`, which had several
defects fixed alongside the pod-level metric addition — no metric was renamed, but
previously-silent or previously-wrong readings on affected hosts will now report correctly:

- Container-ID matching was an unanchored substring (`strings.Contains`), which could in
  principle select the wrong container's cgroup. Now a delimited-segment match.
- The first name-matching `.scope` directory was accepted without checking it actually
  contained a memory-accounting file at all. On cgroup-v1/hybrid hosts, `filepath.WalkDir` can
  reach an unrelated controller subtree (e.g. `blkio`, `cpu`) before `memory`, so the resolver
  could lock onto a directory with no memory-accounting file and silently cache a `0` read for
  the process lifetime. The resolver now keeps walking until it finds a directory that actually
  has one (`memory.current` on v2, `memory.usage_in_bytes` on v1), and reads the correct
  filename pair for whichever it found — so v1 hosts get correctly *container-scoped* numbers
  instead of `0`, not just a `0` that's harder to trigger. This applies to both the container-
  and pod-level resolvers.
- **A host-mounted caller never falls through to the unscoped resolution strategies.** Those
  strategies read from the cgroup root itself, which is only a valid proxy for "this container's
  memory" when the caller mounts its own namespaced cgroup root (the sbom-scanner sidecar, and
  any entrypoint that isn't the Kubernetes DaemonSet). For the DaemonSet, which bind-mounts the
  *host's* cgroup tree, that same root is the whole node. This is a property of the deployment
  topology (`hostCgroupMounted`, passed explicitly by each entrypoint), not of whether a
  container ID happens to be known for a given call — an earlier version of this fix inferred
  it from `ownContainerID == ""` instead, which left the same node-wide misattribution reachable
  through a different door: an empty container ID on the host-mounted DaemonSet (e.g. a
  permanently-cached early-startup race, before this pod's own `ContainerStatuses` entry
  exists) still bind-mounts the host tree, so falling through in that case was exactly as wrong
  as falling through after a failed scoped lookup. Both doors are closed now; a host-mounted
  caller that can't verify a container-scoped directory always reports `0`, never a
  plausible-looking wrong number, regardless of why the container ID wasn't known.
- Scoped to the **systemd** cgroup driver; hosts on the cgroupfs driver still read `0` for
  both the container- and pod-level cgroup metrics (pre-existing, unchanged by this PR —
  tracked as a follow-up, since `findCgroupScopeDir` requires a `.scope`-suffixed name that
  cgroupfs layouts never produce). This is the only remaining declared non-goal; cgroup v1 is
  now fully supported at both the container and pod level.
- The two currently-silent `resolveOwnContainerID` failure paths (missing `POD_NAME`/
  `NAMESPACE_NAME`, and no `ContainerStatuses` entry named `node-agent` yet) now log a
  `Warning`, as does an unresolved container ID on the DaemonSet reaching
  `RegisterPodMemoryMetrics`. Combined with the resolver's own rejection log (also raised to
  `Warning`), the empty-container-ID and cgroup-v1 populations should both become directly
  observable in logs post-deploy.

**On the production data cited during development:** per-pod SigNoz telemetry showed 35% of
live pods reporting `cgroup_bytes == 0` while `rss_bytes > 0`, and 2% showing a smaller genuine
`0 < cgroup_bytes < rss_bytes` inversion. At the time, this was attributed mainly to the
wrong-controller-subtree defect above (cgroup-v1/hybrid hosts). On review, that attribution
isn't fully confirmed: a simpler, v2-compatible explanation — `ownContainerID` resolving to
empty on a permanently-cached early-startup race — is equally consistent with the same observed
zeros, and the true v1-vs-v2 split of the affected 35% couldn't be determined from SigNoz data
alone (no cgroup-version attribute exists in the current telemetry, and live per-node inspection
wasn't available at the time). This PR fixes both failure modes it found either way, but the
35% figure should be read as "pods currently reporting a silent `cgroup_bytes == 0`," not as
confirmed evidence for any one specific mechanism. Because this fix makes cgroup-v1 hosts report
real (non-zero) container-scoped numbers instead of `0`, and raises the pod-level resolver's
rejection log from `Debug` to `Warning`, the actual v1-vs-empty-container-ID split will become
directly observable post-deploy rather than inferred.

### Removed Metrics (not migrated)

The following Prometheus metrics are not present in the OTEL implementation.
See Appendix A of the instrumentation plan for rationale.

| Old Prometheus name | Reason removed |
|---|---|
| `node_agent_program_current_runtime` | Dead code — `ReportEbpfStats` commented out since initial implementation |
| `node_agent_program_current_run_count` | Dead code |
| `node_agent_program_total_runtime` | Dead code |
| `node_agent_program_total_run_count` | Dead code |
| `node_agent_program_map_memory` | Dead code |
| `node_agent_program_map_count` | Dead code |
| `node_agent_program_total_cpu_usage` | Dead code |
| `node_agent_program_per_cpu_usage` | Dead code |

## Histogram Bucket Changes

`node_agent_rule_evaluation_duration` uses new focused buckets covering P99 in the
1–10ms range:

**Old:** `prometheus.ExponentialBuckets(0.001, 2, 10)` → 1ms … 1024s (upper buckets unrealistic)

**New:** `0.5ms, 1ms, 2ms, 5ms, 10ms, 50ms, 500ms, 2s` (covers realistic rule eval latency)

## Update Checklist

When upgrading from Phase 1 to Phase 2:

- [ ] Update Prometheus recording rules referencing old metric names
- [ ] Update Prometheus alerting rules (especially those querying `node_agent_exec_counter`,
      `node_agent_alert_counter`, `node_agent_rule_evaluation_time_seconds`)
- [ ] Update Grafana dashboard panels: replace old metric names with new ones;
      add `event_type` label selector to panels that previously used individual event counters
- [ ] Verify `curl -s :8080/metrics | grep node_agent` returns new names
- [ ] Note that `rule_id` label values now use stable rule IDs, not display names
