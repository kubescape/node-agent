# Fixed-TTL expiration in the evaluation adapter

PR #1018 measured a 42.0160 ms median first-write p99 for the passive adapter after 50,000 entries expired together. Hashicorp measured 0.0468 ms. The mutex profile attributed 99.76% of contention delay to the adapter's full purge. The deployed process-tree cache holds 10,000 entries with a one-minute TTL, so the 50,000-entry result identifies a mechanism but cannot quantify the deployed delay. [Original evaluation](https://github.com/kubescape/node-agent/blob/349273dd2e38fe8ff031595f1afce90478eb4ea6/benchmark/CACHE_MIGRATION.md) · [Process-tree constructor](https://github.com/kubescape/node-agent/blob/30e9c378548fc320b0a652574d74503d11206b6f/pkg/processtree/process_tree_manager.go#L38)

## Cleanup options

Hashicorp v2.0.7 starts a ticker goroutine for positive TTLs and provides no shutdown method. Reads promote live entries in LRU order while preserving their write-time expiry. Jellydator v3.4.1 supports this read behavior with touch-on-hit disabled. Its insertion path evicts the physical LRU entry at capacity, so an expired, recently accessed entry can survive at the expense of a live entry. Its active sweeper calls the same full-batch deletion routine under an exclusive lock. An active prototype would need coordinated startup and shutdown plus measurements that include writes and reads concurrent with a sweep. [Hashicorp constructor and operations](https://github.com/hashicorp/golang-lru/blob/v2.0.7/expirable/expirable_lru.go#L43-L172) · [Jellydator insertion and read](https://github.com/jellydator/ttlcache/blob/v3.4.1/cache.go#L140-L249) · [Full purge](https://github.com/jellydator/ttlcache/blob/v3.4.1/cache.go#L488-L507) · [Sweeper lifecycle](https://github.com/jellydator/ttlcache/blob/v3.4.1/cache.go#L655-L729)

The revised passive adapter tracks keys in last-write order. With one fixed TTL, that order also sorts deadlines. Inspecting the oldest deadline and deleting at most one expired key makes room for one insertion. Renewal moves the existing key to the tail. A mutex serializes writes, promoting reads and capacity eviction. At capacity, the adapter consults Jellydator’s LRU order. A second expiration check accounts for deadlines that elapsed during that lookup. This limits the number of expired victims per write. The index uses one list element and one map entry per retained key. Explicit length inspection still reclaims all expired entries. A quiescent passive cache can retain expired values until another operation reclaims them. [Adapter behavior tests](https://github.com/kubescape/node-agent/blob/349273dd2e38fe8ff031595f1afce90478eb4ea6/internal/ttlcache/cache_test.go)

## Performance evidence

The maintainer requested controlled paired idle-to-first-write and expiration-heavy tests at deployed capacity, plus the corrected workload matrix. The checked-in runner compares p95 and p99 against Hashicorp with a 0% regression budget and paired, multiplicity-adjusted bootstrap intervals. An interval crossing zero is inconclusive. Allocation counts, retained heap under sustained maximum capacity, goroutine lifecycle, system CPU and event throughput are separate requirements for a later production migration. The original system comparison used identical candidate and baseline image digests, so it cannot measure the revised adapter's production effect. [Issue #1014](https://github.com/kubescape/node-agent/issues/1014) · [Maintainer follow-up](https://github.com/kubescape/node-agent/pull/1018#issuecomment-6285930149) · [Benchmark methodology](https://github.com/kubescape/node-agent/blob/349273dd2e38fe8ff031595f1afce90478eb4ea6/benchmark/CACHE_MIGRATION.md)

## Local measurements

Go 1.27.0 on linux/amd64, AMD Ryzen AI 7 350, four Go CPUs on a shared workstation. The paired runner alternated implementation order, used a fresh process per observation, and applied its existing zero-percent regression budget. The expiration-heavy workload used 10,000 hash payloads and a 1 ms TTL.

| Expiration-heavy latency, median of ten per-run percentiles | Hashicorp | Adapter | Paired median change (adjusted interval) |
| --- | ---: | ---: | ---: |
| p95 | 311 ns | 691 ns | +124.1% (+91.7% to +165.8%) |
| p99 | 2,244 ns | 1,818.5 ns | −15.4% (−48.2% to +70.1%) |

The expiration-heavy gate failed on p95. The p99 comparison was inconclusive. The adapter remains experimental.

At 50,000 entries, the post-GC heap stayed at 39,479,808 bytes for the last ten batches of process payloads, versus 31,805,296 bytes for Hashicorp. After clearing, the heap measured 3,831,936 and 6,205,296 bytes respectively. Each batch inserted 50,000 distinct keys. In a separate 10,000-entry process-payload churn benchmark, the adapter used 432 B/op and 4 allocs/op versus 288 B/op and 1 alloc/op for Hashicorp. These memory and allocation diagnostics used one process per implementation.

Reproduce from the repository root, using a fresh output directory for each paired test.

```sh
for scenario in parallel idle; do
  python3 benchmark/cache-migration.py --scenario "$scenario" --capacity 10000 \
    --cpus 4 --pattern expiration --implementations hashicorp adapter \
    --output "/tmp/cache-pr2-$scenario"
done

GOTOOLCHAIN=go1.27.0 go test -c -o /tmp/cache-pr2.test ./internal/ttlcache
for impl in hashicorp adapter; do
  GOMAXPROCS=4 CACHE_BENCH_IMPL="$impl" CACHE_BENCH_MEMORY=1 CACHE_BENCH_CAPACITY=50000 \
    /tmp/cache-pr2.test -test.run '^TestCacheRetainedMemory$' -test.v
  GOMAXPROCS=4 CACHE_BENCH_IMPL="$impl" CACHE_BENCH_CAPACITY=10000 \
    CACHE_BENCH_PATTERN=churn CACHE_BENCH_PAYLOAD=process \
    /tmp/cache-pr2.test -test.run '^$' -test.bench BenchmarkCacheParallel -test.benchmem -test.benchtime=2s
done
```

### First write after idle

At 10,000 entries, each process filled the cache, waited two 100 ms TTLs, then released four readers and performed its first write. Each repetition measured 100 idle cycles. The table reports medians of per-run percentiles in microseconds.

| Latency | Hashicorp (µs) | Adapter (µs) | Gate |
| --- | ---: | ---: | --- |
| write p95 | 23.244 | 71.174 | fail |
| write p99 | 47.423 | 105.357 | fail |
| reader call p95 | 8.305 | 49.017 | fail |
| reader call p99 | 27.366 | 79.574 | fail |
| reader response p95 | 40.446 | 85.365 | fail |
| reader response p99 | 62.552 | 121.592 | fail |

The idle gate classified the comparison as **fail** after 10 pairs.
The separate 50,000-entry hashicorp diagnostic recorded first-write p99 of 0.0385 ms over 100 idle cycles.
The separate 50,000-entry adapter diagnostic recorded first-write p99 of 0.0946 ms over 100 idle cycles.
The 50,000-entry diagnostics used one process per implementation. They do not establish a paired gate at that capacity.

The deployed-capacity expiration-heavy failure blocks adoption. The full workload matrix and system CPU/event-throughput comparison remain outstanding. The production binary does not exercise this adapter.
