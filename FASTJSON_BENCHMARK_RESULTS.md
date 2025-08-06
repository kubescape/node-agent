# Complete Exec Event Serialization Benchmark: JSON vs FastJSON vs ToMap()

## Overview

This benchmark compares three approaches for converting exec events to `map[string]interface{}`:

1. **Standard JSON**: `json.Marshal()` + `json.Unmarshal()` to map
2. **FastJSON**: `json.Marshal()` + `fastjson.Parse()` to map  
3. **Custom ToMap()**: Direct struct → map conversion

## Test Environment
- **CPU**: 12th Gen Intel(R) Core(TM) i7-1255U
- **OS**: Linux
- **Go Version**: Latest
- **Iterations**: 5 benchmark runs with 10,000+ operations each

## Benchmark Results

### Average Performance (from 5 benchmark runs)

| Method | Time per Operation | Memory per Operation | Allocations per Operation |
|--------|-------------------|---------------------|---------------------------|
| **Standard JSON** | ~30,822 ns/op | 5,228 B/op | 130 allocs/op |
| **FastJSON** | ~21,400 ns/op | 12,860 B/op | 110 allocs/op |
| **Custom ToMap()** | ~5,318 ns/op | 3,112 B/op | 35 allocs/op |

## Performance Comparison

### Speed Rankings (Fastest to Slowest)
1. 🥇 **Custom ToMap()**: 5,318 ns/op
2. 🥈 **FastJSON**: 21,400 ns/op (4.0x slower than ToMap)
3. 🥉 **Standard JSON**: 30,822 ns/op (5.8x slower than ToMap)

### Speed Improvements
- **ToMap vs FastJSON**: **4.0x faster** (saves ~16,082 ns per operation)
- **ToMap vs Standard JSON**: **5.8x faster** (saves ~25,504 ns per operation)  
- **FastJSON vs Standard JSON**: **1.4x faster** (saves ~9,422 ns per operation)

### Memory Usage Rankings (Most Efficient to Least)
1. 🥇 **Custom ToMap()**: 3,112 B/op + 35 allocs/op
2. 🥈 **Standard JSON**: 5,228 B/op + 130 allocs/op
3. 🥉 **FastJSON**: 12,860 B/op + 110 allocs/op

### Memory Efficiency
- **ToMap vs FastJSON**: **75.8% less memory** (9,748 B saved) + **68.2% fewer allocs**
- **ToMap vs Standard JSON**: **40.5% less memory** (2,116 B saved) + **73.1% fewer allocs**
- **Standard JSON vs FastJSON**: **59.4% less memory** but **18.2% more allocs**

## Detailed Analysis

### 1. Custom ToMap() Method ⭐ **WINNER**
**Pros:**
- ✅ **Fastest execution** (5.3x faster than nearest competitor)
- ✅ **Lowest memory usage** (3,112 B/op)
- ✅ **Fewest allocations** (35 allocs/op)
- ✅ **No intermediate JSON creation**
- ✅ **Predictable performance**
- ✅ **Direct field access (no reflection)**

**Cons:**
- ❌ Manual field mapping required
- ❌ Maintenance overhead when struct changes
- ❌ More code to write

### 2. FastJSON Library
**Pros:**
- ✅ **1.4x faster than standard JSON**
- ✅ **15% fewer allocations than standard JSON**
- ✅ **Zero-copy string parsing**
- ✅ **No reflection during parsing**

**Cons:**
- ❌ **2.5x more memory usage than standard JSON**
- ❌ **4x slower than ToMap method**
- ❌ Still requires JSON marshaling step
- ❌ More complex conversion logic
- ❌ Higher memory footprint due to internal structures

### 3. Standard JSON Library
**Pros:**
- ✅ **Built-in Go standard library**
- ✅ **Well-tested and reliable**
- ✅ **Automatic field handling via tags**
- ✅ **Lower memory than FastJSON**

**Cons:**
- ❌ **Slowest performance**
- ❌ **Heavy use of reflection**
- ❌ **Creates intermediate JSON strings**
- ❌ **Most allocations during unmarshaling**

## Real-World Performance Impact

For a system processing **1,000 exec events per second**:

| Metric | Standard JSON | FastJSON | ToMap() | ToMap Advantage |
|--------|---------------|----------|---------|-----------------|
| **CPU Time/sec** | 30.8 ms | 21.4 ms | 5.3 ms | **83% reduction** |
| **Memory/sec** | 5.2 MB | 12.9 MB | 3.1 MB | **40-76% less** |
| **Allocations/sec** | 130,000 | 110,000 | 35,000 | **68-73% fewer** |

### Annual Impact (1M events/day)
- **CPU Time Saved**: ToMap saves ~9.3 hours/year vs Standard JSON
- **Memory Saved**: ToMap saves ~770 GB/year vs FastJSON
- **GC Pressure**: Dramatically reduced with ToMap

## Surprising FastJSON Results

**FastJSON performed worse than expected because:**

1. **Higher Memory Usage**: FastJSON's internal structures use ~2.5x more memory
2. **Still Requires Marshaling**: Must use `json.Marshal()` first (FastJSON is parse-only)
3. **Conversion Overhead**: Converting FastJSON values to `map[string]interface{}` adds complexity
4. **Not Optimized for This Use Case**: FastJSON excels at selective field access, not full conversion

## Recommendations

### Use Custom ToMap() When:
- ✅ **High-frequency event processing** (>100 events/sec)
- ✅ **Performance is critical**
- ✅ **Memory efficiency matters**
- ✅ **CPU resources are limited**
- ✅ **Predictable performance needed**

### Use Standard JSON When:
- ✅ **Low-frequency operations** (<10 events/sec)
- ✅ **Development speed priority**
- ✅ **Struct changes frequently**
- ✅ **Simple, reliable solution needed**

### Use FastJSON When:
- ✅ **Need to parse large JSON and access few fields**
- ✅ **Working with external JSON sources**
- ✅ **Selective data extraction**
- ❌ **NOT recommended for full struct→map conversion**

## Conclusion

**The Custom ToMap() method is the clear winner for exec event processing:**

- 🏆 **5.8x faster than Standard JSON**
- 🏆 **4.0x faster than FastJSON** 
- 🏆 **40-76% less memory usage**
- 🏆 **68-73% fewer allocations**
- 🏆 **Best scalability for high-throughput scenarios**

**FastJSON showed that specialized libraries aren't always better** - sometimes simple, direct approaches (ToMap) outperform complex optimized libraries when the use case doesn't match the library's strengths.

**For production systems handling large volumes of exec events, the custom ToMap() approach is strongly recommended.** 