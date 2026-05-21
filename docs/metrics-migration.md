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
