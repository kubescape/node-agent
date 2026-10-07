# TTL cache migration experiments

The production prototype uses ttlcache v3.4.1 without `Start`, callbacks, or
loaders. Reads promote LRU recency without renewing TTL. Writes call
`DeleteExpired` before insertion, so expired recent entries do not displace live
entries. `Has` rejects expired entries immediately and does not promote recency;
`Len` reclaims expiration and returns live entry count. Both differ from
Hashicorp's retained-entry `Contains`/`Len` behavior. Nonpositive TTL means no
expiration, replacing Hashicorp's ten-year sentinel; nonpositive capacity means
unlimited. Expired references remain until writes, length inspection, clearing,
or disposal. Unlimited caches have no general memory bound.

## Evaluation outcome: blocked (2026-10-05)

The checked first-write experiment failed the selected 0% latency budget after
ten paired repetitions, each with 100 idle cycles, capacity 50,000, four CPUs,
100 ms TTL, integer keys, and representative file-hash payloads. Filling was
validated before expiration in every trial. After inactivity, Hashicorp retained
zero entries and the adapter retained all 50,000 expired entries.

| Median of per-run percentiles | Hashicorp | Adapter |
| --- | ---: | ---: |
| Write p95 | 0.0259 ms | 35.8209 ms |
| Write p99 | 0.0468 ms | 42.0160 ms |
| Reader call p99 | 0.0303 ms | 41.9898 ms |

All six primary latency comparisons failed their Bonferroni-adjusted paired
bootstrap gate. For write p99, the relative-change interval was
**+56,338% to +170,551%**, entirely above the 0% budget. A separate ten-cycle
mutex/block profile attributed **99.76% of mutex contention delay** to
`ttlcache.DeleteExpired` called by the adapter's `Set`. This identifies the
synchronous purge of the entire expired batch as the cause of reader stalls.

The adapter, process-tree prototype, regression tests, and experiment harness
are retained as evaluation work. Other caches remain on Hashicorp.
The system harness changes, remaining migration, complete benchmark matrix,
repository-wide privileged checks, and system benchmark were not executed:
they remain blocked by this failed prototype gate. Publication of the evaluation
branch was explicitly authorized after the failed gate; this is not an accepted
production migration or a resolution of #1014. No PR was created, and Docker
was not started.

Passed: adapter/process-tree race and leak tests; ten repetitions of the core
unit tests; process-tree subtree race tests; focused builds and vet; Python
latency-gate regression tests; and whitespace checks. Allocation/heap benchmark
support exists but no memory-plateau acceptance result is claimed.

Local evidence (not committed):

- `/home/linux/.cache/node-agent-1014-idle-checked-50000-cpu4/`: raw samples,
  source snapshots, binary, manifest, formal `report.json`, and `benchstat.txt`.
- `/home/linux/.cache/node-agent-1014-profiles/`: adapter and Hashicorp
  mutex/block profiles and raw profiling experiment output.
- The earlier four-implementation run at
  `/home/linux/.cache/node-agent-1014-idle-50000-cpu4/` was interrupted to add
  full-batch validation and is marked diagnostic-only. It is not gate evidence.

## First migration gate

Run from the repository root with Go 1.27. The output directory must not exist:

```sh
python3 benchmark/cache-migration.py \
  --scenario idle --capacity 50000 --cpus 4 --trials 100 \
  --output /absolute/path/to/fresh-output
```

Each process fills the cache with precomputed file-hash values, waits two TTLs,
then releases concurrent readers and performs the first write. Write latency,
reader call latency, and reader response latency (including scheduling delay
since release) are recorded separately, including individual samples and maxima.
The current experiment also checks that filling completed before the oldest
entry expired, and records physical retention after inactivity. Mutex/block
profiles are needed to confirm reader overlap with cleanup; barrier release alone
does not establish lock contention.

Every implementation has identical capacity, TTL, values and idle duration.
Active ttlcache must physically expire a readiness sentinel before testing, then
stop and join its sweeper at exit. Hashicorp has exactly one cache per process,
including Go benchmark calibration. Each repetition runs in a fresh process;
the implementation order reverses on alternate repetitions.

`observations.json` contains samples. `manifest.json` and `sources/` capture the
baseline SHA, toolchain, dimensions, tracked diff and exact experiment sources,
including untracked prototype files. The linked test binary is retained for
replay. No Docker daemon, Kubernetes cluster, or Git remote is changed.

The gate compares adapter/Hashicorp p95 and p99 for each latency metric. It uses
paired bootstrap intervals of median relative changes, a fixed seed, 100,000
resamples, and Bonferroni correction over 270 predeclared possible comparisons
for 95% family-wide coverage. An upper bound <=0% passes; a lower bound >0%
fails; otherwise the result is inconclusive. Inconclusive experiments extend from
ten to thirty pairs. Missing, non-finite, or insufficient evidence cannot pass.
Fail/inconclusive exits nonzero and blocks migration. Publishing an evaluation
branch requires explicit authorization and must retain the failed-gate findings.

## Steady-state and allocation diagnostics

Use `--scenario parallel` for sampled `RunParallel` p95/p99 latency, and
`--scenario allocations` for separate, uninstrumented ns/op, B/op and allocs/op.
Use `--pattern hits|misses|churn|expiration`, `--payload int|hash|process`, and
capacities 1000/10000/50000 with CPU settings 1/4/16. Allocation diagnostics do
not establish latency equivalence. The latency sample buffer is bounded per
worker, samples every 64 operations, and retains the most recent samples.

`TestCacheRetainedMemory` is an opt-in isolated experiment enabled by
`CACHE_BENCH_MEMORY=1` and `CACHE_BENCH_IMPL`. It inserts twenty capacity-sized
batches of newly allocated process-tree values, checks stored entry count, and
records post-GC heap bytes after each batch and clearing. Read its raw samples
and heap profiles; a successful cardinality assertion alone does not prove a
stable memory plateau.

## Scope of an unsuccessful prototype

If the first-write gate fails, retain the prototype and its evidence for review.
Do not migrate other subsystems, modify the system benchmark harness, start
Docker, or create a PR. Publish the evaluation only on explicit authorization;
do not describe it as a completed migration. The system benchmark safety/telemetry
changes and repository-wide privileged validation remain gated on a successful
prototype. Baseline package tests are not evidence of migration completion.
