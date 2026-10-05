package ttlcache

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/hashicorp/golang-lru/v2/expirable"
	jellycache "github.com/jellydator/ttlcache/v3"
	"go.uber.org/goleak"
)

// Invoke exactly one benchmark/scenario per process, with -count=1 and one
// -cpu value. Reuse the fixture across Go's calibration invocations so the
// Hashicorp baseline creates exactly one unstoppable sweeper per process.
var benchmarkFixture any
var benchmarkStop func()

func TestMain(m *testing.M) {
	code := m.Run()
	if benchmarkStop != nil {
		benchmarkStop()
	}
	os.Exit(code)
}

func TestActiveComparisonLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for range 10 {
		c := newBenchmarkCache[int]("active", 10, time.Second)
		c.set(1, 1)
		benchmarkStop()
	}
}

type benchmarkCache[V any] struct {
	get    func(int) (V, bool)
	set    func(int, V)
	clear  func()
	stored func() int
}

func newBenchmarkCache[V any](implementation string, capacity int, ttl time.Duration) benchmarkCache[V] {
	switch implementation {
	case "hashicorp":
		c := expirable.NewLRU[int, V](capacity, nil, ttl)
		return benchmarkCache[V]{get: c.Get, set: func(k int, v V) { c.Add(k, v) }, clear: c.Purge, stored: c.Len}
	case "adapter":
		c := New[int, V](capacity, ttl)
		return benchmarkCache[V]{get: c.Get, set: c.Set, clear: c.DeleteAll, stored: func() int {
			metrics := c.cache.Metrics()
			return int(metrics.Insertions - metrics.Evictions)
		}}
	case "passive", "active":
		c := jellycache.New[int, V](jellycache.WithCapacity[int, V](uint64(capacity)),
			jellycache.WithTTL[int, V](ttl), jellycache.WithDisableTouchOnHit[int, V]())
		if implementation == "active" {
			// Has alone cannot prove the sweeper is running: expiration is checked
			// even in passive mode. Wait for physical eviction of a sentinel.
			var zero V
			c.Set(-1, zero, time.Millisecond)
			done := make(chan struct{})
			go func() { c.Start(); close(done) }()
			deadline := time.Now().Add(time.Second)
			for c.Metrics().Evictions == 0 {
				if time.Now().After(deadline) {
					panic("active sweeper did not evict its readiness sentinel")
				}
				time.Sleep(time.Millisecond)
			}
			benchmarkStop = func() { c.Stop(); <-done }
		}
		return benchmarkCache[V]{
			get: func(k int) (V, bool) {
				if item := c.Get(k); item != nil {
					return item.Value(), true
				}
				var zero V
				return zero, false
			},
			set: func(k int, v V) { c.Set(k, v, jellycache.DefaultTTL) }, clear: c.DeleteAll,
			stored: func() int {
				metrics := c.Metrics()
				return int(metrics.Insertions - metrics.Evictions)
			},
		}
	default:
		panic("CACHE_BENCH_IMPL must be hashicorp, adapter, passive, or active")
	}
}

func envInt(name string, fallback int) int {
	if s := os.Getenv(name); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v <= 0 {
			panic(name + " must be a positive integer")
		}
		return v
	}
	return fallback
}

func percentile(samples []time.Duration, quantile float64) float64 {
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return float64(samples[int(math.Ceil(quantile*float64(len(samples))))-1])
}

type benchmarkHashes struct{ SHA1Hash, MD5Hash string }

func benchmarkProcess(i int) armotypes.Process {
	return armotypes.Process{PID: uint32(i + 1), Comm: "worker", Children: []armotypes.Process{
		{PID: uint32(i + 2), Comm: "child"},
	}}
}

func BenchmarkCacheParallel(b *testing.B) {
	if os.Getenv("CACHE_BENCH_IMPL") == "" {
		b.Skip("use benchmark/cache-migration.py to run isolated comparisons")
	}
	switch os.Getenv("CACHE_BENCH_PAYLOAD") {
	case "int", "":
		runParallel(b, func(i int) int { return i })
	case "hash":
		runParallel(b, func(i int) *benchmarkHashes {
			return &benchmarkHashes{fmt.Sprintf("%040x", i), fmt.Sprintf("%032x", i)}
		})
	case "process":
		runParallel(b, benchmarkProcess)
	default:
		b.Fatal("unknown CACHE_BENCH_PAYLOAD")
	}
}

func runParallel[V any](b *testing.B, makeValue func(int) V) {
	capacity := envInt("CACHE_BENCH_CAPACITY", 1000)
	pattern := os.Getenv("CACHE_BENCH_PATTERN")
	ttl := time.Minute
	if pattern == "expiration" {
		ttl = time.Millisecond
	}
	if benchmarkFixture == nil {
		benchmarkFixture = newBenchmarkCache[V](os.Getenv("CACHE_BENCH_IMPL"), capacity, ttl)
	}
	c := benchmarkFixture.(benchmarkCache[V])
	c.clear()
	values := make([]V, capacity)
	for i := range values {
		values[i] = makeValue(i)
		c.set(i, values[i])
	}
	if pattern != "hits" && pattern != "misses" && pattern != "churn" && pattern != "expiration" {
		b.Fatal("CACHE_BENCH_PATTERN must be hits, misses, churn, or expiration")
	}
	latency := os.Getenv("CACHE_BENCH_LATENCY") == "1"
	var worker atomic.Uint64
	var mu sync.Mutex
	var samples []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		seed := worker.Add(1)
		// Bounded per-worker samples, separate from allocation measurements.
		var local []time.Duration
		if latency {
			local = make([]time.Duration, 0, 8192)
		}
		iteration := uint64(0)
		for pb.Next() {
			seed ^= seed << 13
			seed ^= seed >> 7
			seed ^= seed << 17
			key := int(seed % uint64(capacity))
			measure := latency && iteration%64 == 0
			var start time.Time
			if measure {
				start = time.Now()
			}
			switch pattern {
			case "hits", "expiration":
				if seed%10 < 9 {
					_, _ = c.get(key)
				} else {
					c.set(key, values[key])
				}
			case "misses":
				if seed%10 < 9 {
					_, _ = c.get(key + capacity)
				} else {
					c.set(key, values[key])
				}
			case "churn":
				c.set(int(seed), values[key])
			}
			if measure {
				d := time.Since(start)
				if len(local) < cap(local) {
					local = append(local, d)
				} else {
					local[(iteration/64)%uint64(len(local))] = d
				}
			}
			iteration++
		}
		if latency {
			mu.Lock()
			samples = append(samples, local...)
			mu.Unlock()
		}
	})
	b.StopTimer()
	if len(samples) != 0 {
		b.ReportMetric(percentile(samples, .95), "p95-ns")
		b.ReportMetric(percentile(samples, .99), "p99-ns")
		b.ReportMetric(float64(len(samples)), "samples")
	}
}

// TestCacheIdleLatency is deliberately separate from the steady-state
// benchmarks: a rare first-write spike must not disappear in a mixed percentile.
func TestCacheIdleLatency(t *testing.T) {
	if os.Getenv("CACHE_BENCH_IMPL") == "" {
		t.Skip("explicit isolated performance experiment")
	}
	capacity := envInt("CACHE_BENCH_CAPACITY", 50000)
	trials := envInt("CACHE_BENCH_TRIALS", 100)
	readers := runtime.GOMAXPROCS(0)
	ttl := time.Duration(envInt("CACHE_BENCH_TTL_MS", 100)) * time.Millisecond
	c := newBenchmarkCache[*benchmarkHashes](os.Getenv("CACHE_BENCH_IMPL"), capacity, ttl)
	values := make([]*benchmarkHashes, capacity)
	for i := range values {
		values[i] = &benchmarkHashes{fmt.Sprintf("%040x", i), fmt.Sprintf("%032x", i)}
	}
	writes := make([]time.Duration, 0, trials)
	fills := make([]time.Duration, 0, trials)
	retained := make([]int, 0, trials)
	readCalls := make([]time.Duration, 0, trials*readers)
	readResponses := make([]time.Duration, 0, trials*readers)
	for range trials {
		c.clear()
		fill := time.Now()
		for i, value := range values {
			c.set(i, value)
		}
		fills = append(fills, time.Since(fill))
		if c.stored() != capacity {
			t.Fatalf("filled %d entries, expected %d; increase CACHE_BENCH_TTL_MS", c.stored(), capacity)
		}
		if _, found := c.get(0); !found {
			t.Fatalf("first entry expired during fill (%s); increase CACHE_BENCH_TTL_MS", time.Since(fill))
		}
		// Let Hashicorp's asynchronous bucket cleanup finish too. The TTL and
		// idle interval are identical for every implementation.
		time.Sleep(2 * ttl)
		retained = append(retained, c.stored())
		start := make(chan struct{})
		var ready, finished sync.WaitGroup
		var release time.Time
		calls := make([]time.Duration, readers)
		responses := make([]time.Duration, readers)
		for reader := range readers {
			ready.Add(1)
			finished.Add(1)
			go func() {
				defer finished.Done()
				ready.Done()
				<-start
				call := time.Now()
				_, _ = c.get(reader % capacity)
				calls[reader] = time.Since(call)
				responses[reader] = time.Since(release)
			}()
		}
		ready.Wait()
		release = time.Now()
		close(start)
		write := time.Now()
		c.set(capacity, values[0])
		writes = append(writes, time.Since(write))
		finished.Wait()
		readCalls = append(readCalls, calls...)
		readResponses = append(readResponses, responses...)
	}
	metrics := map[string]any{"implementation": os.Getenv("CACHE_BENCH_IMPL"), "capacity": capacity,
		"cpus": readers, "trials": trials, "ttl_ms": ttl.Milliseconds(),
		"fill_samples_ns": fills, "retained_after_idle": retained}
	for name, samples := range map[string][]time.Duration{"write": writes, "reader_call": readCalls, "reader_response": readResponses} {
		metrics[name+"_p95_ns"] = percentile(samples, .95)
		metrics[name+"_p99_ns"] = percentile(samples, .99)
		metrics[name+"_max_ns"] = float64(samples[len(samples)-1])
		metrics[name+"_samples_ns"] = samples
	}
	data, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("CACHE_IDLE_RESULT=%s\n", data)
}

func TestCacheRetainedMemory(t *testing.T) {
	if os.Getenv("CACHE_BENCH_MEMORY") != "1" {
		t.Skip("explicit isolated heap experiment")
	}
	capacity := envInt("CACHE_BENCH_CAPACITY", 50000)
	c := newBenchmarkCache[armotypes.Process](os.Getenv("CACHE_BENCH_IMPL"), capacity, time.Minute)
	snapshot := func() uint64 {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		runtime.KeepAlive(c)
		return stats.HeapAlloc
	}
	baseline := snapshot()
	observations := make([]uint64, 0, 20)
	for cycle := range 20 {
		for i := range capacity {
			key := cycle*capacity + i
			c.set(key, benchmarkProcess(key))
		}
		if c.stored() != capacity {
			t.Fatalf("stored entry count %d differs from capacity %d", c.stored(), capacity)
		}
		observations = append(observations, snapshot())
	}
	populated := snapshot()
	c.clear()
	cleared := snapshot()
	data, err := json.Marshal(map[string]any{"implementation": os.Getenv("CACHE_BENCH_IMPL"),
		"capacity": capacity, "payload": "process", "baseline_heap_bytes": baseline,
		"heap_samples_bytes": observations, "populated_heap_bytes": populated, "cleared_heap_bytes": cleared})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("CACHE_MEMORY_RESULT=%s\n", data)
}
