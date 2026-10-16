# TTL cache migration experiments

The evaluation adapter uses ttlcache v3.4.1 without `Start`, callbacks, or
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

The adapter, regression tests, and experiment harness are retained as evaluation
work. Production process-tree caching has been restored to Hashicorp pending a
passing migration gate. All other production caches also remain on Hashicorp.
The original evaluation did not execute system harness changes, the remaining
migration, the complete benchmark matrix, repository-wide privileged checks, or
the system benchmark. These historical results do not establish an accepted
production migration or a resolution of #1014.

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
worker at 16,384 entries, samples every 64 operations, and retains the most
recent samples. This exceeds the runner's unchanged 10,000-sample minimum even
with one worker; shorter or slower runs can still be rejected for insufficient
samples.

`TestCacheRetainedMemory` is an opt-in isolated experiment enabled by
`CACHE_BENCH_MEMORY=1` and `CACHE_BENCH_IMPL`. It inserts twenty capacity-sized
batches of newly allocated process-tree values, checks stored entry count, and
records post-GC heap bytes after each batch and clearing. Read its raw samples
and heap profiles; a successful cardinality assertion alone does not prove a
stable memory plateau.

## Scope of an unsuccessful prototype

If the first-write gate fails, retain the evaluation adapter and evidence for
review while keeping Hashicorp in production. Further subsystem migration
requires a passing gate. Local package, component, and system checks validate
the evaluation PR; they cannot override the failed adapter latency gate or
establish migration completion.

## Review follow-up (2026-10-16)

Production process-tree caching is restored to the upstream Hashicorp cache.
The passive adapter remains available only for evaluation; its synchronous
full-batch purge is unchanged and has not passed the migration gate. The
production dependency graph contains neither ttlcache nor goleak.

Parallel latency sampling now retains up to 16,384 samples per worker while
keeping the runner's 10,000-sample minimum and sampling every 64 operations.
A subprocess regression test runs 1,048,576 operations at one CPU and verifies
that 16,384 samples are retained. Python tests cover rejection below the minimum
and acceptance at the minimum and buffer capacity. A fresh one-CPU hits/int run
completed 30 pairs with 15,625–16,384 samples per observation and produced a
failed gate report. Other checks were active during that run, so it verifies
sampling/report generation rather than replacing the controlled idle experiment.

The component-test workflow downloads dependencies before executing tests and
retries downloads at most three times, with 5- and 10-second waits. Test
execution itself is not retried. Immediate success, transient failure recovery,
and permanent failure were verified against the workflow's actual shell block.

Local validation with Go 1.27:

- Focused adapter/process-tree race tests and vet passed, as did all five Python
  runner tests and workflow syntax validation.
- The repository-wide privileged race run passed 73 packages; 27 had no tests.
  Host FIM and malware-manager packages failed with races that also reproduce
  on the unmodified upstream `493f1011` snapshot. Those files are unchanged.
- `Test_02_AllAlertsFromMaliciousApp` passed in a disposable Kind cluster in
  310.57 seconds, using the existing test chart and storage v0.0.352.
- Independent upstream and candidate container builds produced the same image
  digest, confirming that the evaluation changes do not alter that artifact.

Current local logs, benchmark observations, source snapshots, and component-test
CPU/memory plots are retained under
`/home/linux/.cache/node-agent-pr1018-20261016/` (not committed).

The system harness completed its baseline measurement, then hit a chart download
timeout before the candidate measurement. The candidate was measured in a fresh
disposable cluster with identical cached chart versions, unchanged benchmark
functions, a 120-second warmup, and a 600-second load window. This was a resumed
comparison, not an uninterrupted successful harness run.

| System metric | Upstream | Candidate | Change |
| --- | ---: | ---: | ---: |
| Mean CPU (cores) | 0.1458 | 0.2013 | +38.0% |
| CPU p95 (cores) | 0.1582 | 0.2100 | +32.7% |
| Mean memory (MiB) | 314.34 | 314.00 | -0.11% |
| Peak memory (MiB) | 317.76 | 318.81 | +0.33% |
| Current-counter event rate (events/s) | 1635.01 | 1633.56 | -0.09% |

The existing 10% resource gate **failed** on mean and p95 CPU. The independently
built images have identical digests, so this run cannot attribute the observed
CPU difference to the evaluation changes or establish a passing comparison.
The legacy harness event queries returned no series; event rates above use
separate current OTEL counter queries over the same ten-minute windows. There
were no rule-counter series, so rule-evaluation throughput is unverified. Each
resource comparison has 21 samples. Heap, allocation, and CPU profiles, plots,
raw counters, and the failed gate output are retained with the local evidence.
The complete cache matrix and heap-plateau acceptance remain unrun; neither
system results nor package tests override the failed cache latency gate.

## Parallel workload correction (2026-10-16)

Parallel workers now draw the operation and key separately from a deterministic
per-worker PCG generator. The previous shared draw selected reads with
`seed % 10 < 9` and keys with `seed % capacity`. At capacities 1,000, 10,000,
and 50,000 this split reads and writes into disjoint key sets. Expiration reads
therefore missed every initialized key after its TTL, without reading keys
renewed by writes. Earlier parallel observations do not validate the intended
mixed workload and must be rerun; the separate idle experiment above is
unaffected by this selector correction and its failed gate remains in force.

`TestParallelExpirationRenewal` checks all three capacities with a fixed seed.
It expires the initial population, executes the same selector as the benchmark,
and verifies that writes renew keys that subsequent reads find, while reads
remain approximately 90% of operations. Renewals use a long TTL in this test
so correctness does not depend on machine speed; measured expiration benchmarks
retain their 1 ms TTL. With the old correlated selector the test finds zero
renewed/read keys at every capacity.

Focused adapter/process-tree race tests, vet, the single-CPU subprocess
regression, all five Python runner tests, formatting and whitespace checks
passed after the correction. The corrected expiration runner completed ten
Hashicorp/adapter pairs at capacity 1,000, one CPU and integer payloads, with
all observations meeting the 10,000-sample minimum. Report generation completed
and the unchanged 0% gate failed (median p95 change +113.3%, p99 +403.2%).
This smoke run overlapped local checks and is not controlled performance
acceptance; the full matrix and heap plateau remain unrun. Raw observations,
source snapshots and report are retained locally in
`/home/linux/.cache/node-agent-pr1018-expiration-independent-20261016/`.
