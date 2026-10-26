# gVisor start trial record

**Status: reusable template.** For measured results, see the
[26 October local ARM64 trial](experiments/gvisor-start-20261026/README.md).
That trial found an unexplained missed start and does not pass the integration
gates. The pending entries below are placeholders for another trial record.

This is a template for the live experiment from
[design #23](https://github.com/kubescape/designs-and-proposals/pull/23).
Neither the merged receiver nor the offline checker establishes live coverage.
Copy this record for a real trial and replace pending entries with measured
results and sanitized evidence references. Do not mark a gate passed from a
synthetic sender test or an offline checker result alone.

## Environment and ownership

| Item | Recorded value |
|---|---|
| Trial date and operator | Pending |
| Linux distribution, kernel and architecture | Pending |
| Exact runsc version/commit and binary checksum | Pending |
| containerd and CRI versions | Pending |
| node-agent version/commit and configuration | Pending |
| Probe version/commit | Pending |
| Runtime root and namespace | Pending |
| Sandbox/root/child ID relationship from runtime inventory | Pending |
| Selected trace metadata and initialization configuration | Pending |
| Receiver owner, socket permissions and runtime access | Pending |
| Owner of Default trace session, conflict behavior | Pending |

Record actual commands against the pinned runtime and any deviations from
[the procedure](gvisor-start-probe.md). Configure tracing before startup and
never overwrite another monitor's session with `--force`. Trace configuration
is host setup, not something this branch installs.

## Trial gates

| Scenario | Expected evidence | Result |
|---|---|---|
| Ordinary container baseline | Runtime IDs/times and host process/network observations | Pending |
| One gVisor container | Independently recorded runtime ID/times, trace start and host comparison | Pending |
| Twenty repeated starts | Expected vs observed per-ID counts, 20/20 starts without unexplained misses | Pending |
| Two concurrent sandboxes | Overlapping runtime lifetimes, distinct IDs/connections, no identity crossover | Pending |
| Root and child privacy fixtures | Canary used in both argv and cwd; absent from retained/forwarded output and errors | Pending |
| Receiver absent and slow | Startup impact, retry delay, sender/local loss, bounded resources | Pending |
| Receiver restart | Trace-session ownership, recovery behavior and any missed early starts | Pending |
| Normal exit and forced termination | Runtime state vs trace transport; no stop inferred from disconnect alone | Pending |
| Controlled outbound, refused connection and DNS | Compare runtime/trace/host evidence and name only the observed behavior | Pending |

## Sanitized evidence and interpretation

- Runtime-derived expected manifest and provenance: pending.
- Probe exit status, checker invocation and result: pending.
- Sanitized observation files, including stderr and privacy review: pending.
- Versioned workload and harmless canary fixture: pending.
- Expected/observed starts and timing comparison: pending.
- Sender-reported loss and separately measured local loss: pending.
- Host eBPF comparison, including what could not be observed: pending.
- Startup latency and CPU/memory measurements with method: pending.
- Failures, missing events and unexplained differences: pending.

The start hook precedes application execution. Receiver timestamps are
observation times, not runtime start timestamps. Correlating exact IDs does
not establish actor/session identity or Kubernetes attribution. The current
probe uses a manually supplied allowlist, not node-agent's runtime inventory.

## Decision before integration

State which gates passed, failed or remain untested, with supporting evidence.
Unexplained missed starts, identity ambiguity or privacy failures block the
verified-start integration. Source-health gaps must be recorded and addressed
before claiming reliable collection. Network and stop integration require
separate source validation. Managed GKE remains unverified unless its runtime
configuration and socket access are independently demonstrated.

**Current decision: pending live Linux trial.**
