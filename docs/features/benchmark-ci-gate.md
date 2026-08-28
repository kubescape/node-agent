---
type: feature
status: done
owner: armosec/node-agent
scope: repo
related_code:
  - benchmark/compare-metrics.py
  - benchmark/dedup-bench.sh
  - .github/workflows/benchmark.yaml
---

# Performance Benchmark CI Gate

`Performance Benchmark / benchmark` (`.github/workflows/benchmark.yaml`) runs
one before/after eBPF dedup benchmark pass per PR and gates on
`benchmark/compare-metrics.py --check`. This doc covers the gate's
methodology and the false-positive fix from
[#519](https://github.com/armosec/private-node-agent/issues/519).

## Why Peak CPU is gated on p95, not max

Each run samples node-agent CPU at 1-minute rate-window granularity over a
10-minute load window (`benchmark/dedup-bench.sh`), then reports a single
"peak" = `max()` of that sample. Gating a relative delta on two independent
max-of-samples draws (one BEFORE, one AFTER) is biased toward false
positives by construction: scheduling jitter, noisy-neighbor effects, and GC
pauses can only push an *observed* peak up from a run's true behavior, never
down. #519 documented this producing failures on a majority of runs in every
week since the check was introduced, including four identical-commit reruns
of the same PR landing anywhere from +1.8% to +10.2%.

`compare-metrics.py` now gates Peak CPU on the 95th percentile
(`PEAK_CPU_P95_THRESHOLD`, default 10%) instead of the strict max. p95 drops
the single noisiest sample per run — in practice, exactly where that jitter
spike lands. The true max is still computed and shown in the report table
("Peak CPU (cores)") for visibility; it just no longer gates the build.

Avg CPU and Avg/Peak Memory are unaffected — they don't show this bias (see
#519's evidence) and remain gated on `SIGNIFICANT_THRESHOLD` (5%) against
their existing mean/max statistics.

### Verification

Re-running the updated gate against the raw per-sample CSVs behind three of
#519's real false-positive cases (PR #520 and two identical-commit reruns of
PR #507, pulled from each run's `benchmark-results` artifact):

| Case | Peak CPU (max) delta | Old gate (>5%) | Peak CPU (p95) delta | New gate (>10%) |
|---|---|---|---|---|
| PR #520 (dependency pin bump, no runtime change) | +8.7% | FAIL | -0.4% | pass |
| PR #507 rerun 1 (identical commit) | +10.2% | FAIL | +2.0% | pass |
| PR #507 rerun 2 (identical commit) | +8.3% | FAIL | +3.2% | pass |

A synthetic +20% sustained CPU regression (scaling every node-agent CPU
sample in a real run's AFTER data) still fails both Avg CPU and Peak CPU
(p95) at their new thresholds, confirming the gate still catches genuine
regressions.

## Before-image baseline (not changed in this fix)

`before_image` defaults to the latest GitHub release tag
(`quay.io/armosec/node-agent:<tag>`), not a merge-base rebuild of the PR's
target branch. Between releases, a PR's reported delta silently includes
everything else merged since the last release, not just its own diff — #519
documents a same-afternoon case where two different PRs' benchmark runs
compared against two different release baselines 40 minutes apart.

This was evaluated as a candidate fix alongside the p95 change but not
implemented here: there's no existing per-commit image published on merges
to `main` to reference cheaply, so a correct fix means building a fresh
"before" image from the merge-base commit inside every benchmark run — a new
~10-15 minute build step with its own failure modes (arbitrary historical
commits may not build cleanly with current tooling), and not verifiable
without a live CI run. The p95 change above already resolves every
false-positive case in #519's evidence on its own. Tracked as a deliberate
follow-up if release-cut-adjacent staleness continues to cause problems in
practice.

## pprof capture (heap, allocs, cpu)

`compare-metrics.py`'s Prometheus-derived numbers say a metric moved, not
why — a peak-memory failure on PR #454 could only be root-caused by reading
the resolver's source and inferring what was likely allocating, not by
looking at an actual profile. `dedup-bench.sh` now captures real pprof
profiles alongside the existing CSVs/PNGs, for both the before and after
runs:

- `_helm_install_kubescape_oss`/`_helm_install_armo` set
  `nodeAgent.env[0]={name: ENABLE_PROFILER, value: 1}`, which gates
  `cmd/main.go`'s existing (pre-dating this PR) `localhost:6060` pprof
  server.
- `collect_pprof_profiles` (called right after `collect_metrics`, still
  inside the `start_port_forward`/`stop_port_forward` window, so it doesn't
  extend the run) `kubectl port-forward`s each node-agent pod's `:6060` —
  the same technique already used for the Prometheus and OTLP-sink loopback
  listeners elsewhere in this repo's test tooling, which works for a
  loopback-only bind because port-forward operates inside the pod's network
  namespace — then pulls `/debug/pprof/heap`, `/debug/pprof/allocs`, and a
  `PPROF_CPU_SECONDS`-long `/debug/pprof/profile` into
  `<pod-name>_{heap,allocs,cpu}.pprof`.
- Best-effort throughout: a capture failing (an older before-image without
  `ENABLE_PROFILER` support, a pod that rolled mid-call) logs a warning and
  moves on — it must never fail the benchmark run itself.

These land in the existing `benchmark-results` artifact
(`.github/workflows/benchmark.yaml`'s `Upload artifacts` step already
uploads the whole `benchmark-output/` tree with `if: always()`, 30-day
retention) — no new upload step needed. To review after a run:

```bash
gh run download <run-id> -n benchmark-results
go tool pprof -top before/<pod>_heap.pprof
go tool pprof -top -base before/<pod>_heap.pprof after/<pod>_heap.pprof   # diff
go tool pprof -http=: after/<pod>_cpu.pprof                                # flamegraph, local only
```
