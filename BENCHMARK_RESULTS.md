# Exec Event Serialization Benchmark Results

## Overview

This benchmark compares two approaches for converting exec events to `map[string]interface{}`:
1. **JSON Marshal/Unmarshal**: Convert struct → JSON → map[string]interface{}
2. **Custom ToMap()**: Direct struct → map[string]interface{} conversion

## Test Environment
- **CPU**: 12th Gen Intel(R) Core(TM) i7-1255U
- **OS**: Linux
- **Go Version**: Latest
- **Iterations**: Multiple runs with 10,000+ operations each

## Benchmark Results

### Average Performance (from 5 benchmark runs)

| Method | Time per Operation | Memory per Operation | Allocations per Operation |
|--------|-------------------|---------------------|---------------------------|
| JSON Marshal/Unmarshal | ~17,908 ns/op | 5,228 B/op | 130 allocs/op |
| Custom ToMap() | ~2,796 ns/op | 3,112 B/op | 35 allocs/op |

### Performance Comparison

#### Speed Improvement
- **Custom ToMap() is ~6.4x faster** than JSON approach
- Time saved per operation: ~15,112 ns (15.1 µs)
- For 1 million events: **~15 seconds saved**

#### Memory Efficiency
- **40.5% less memory usage** (3,112 vs 5,228 bytes)
- **73.1% fewer allocations** (35 vs 130 allocations)
- No intermediate JSON string creation (saves ~656 bytes per operation)

#### CPU Utilization
- JSON approach: High CPU usage due to reflection and string parsing
- ToMap approach: Direct field access, minimal CPU overhead

## Detailed Analysis

### JSON Marshal/Unmarshal Approach
**Pros:**
- Automatic field inclusion via JSON tags
- No custom code maintenance
- Handles nested structures automatically

**Cons:**
- Requires reflection for marshaling
- Creates intermediate JSON string (~656 bytes)
- JSON parsing overhead for unmarshaling
- Higher memory allocations
- Significantly slower

### Custom ToMap() Method
**Pros:**
- Direct field access (no reflection)
- No intermediate data creation
- Much faster execution
- Lower memory footprint
- Fewer allocations
- Full control over output format

**Cons:**
- Requires manual field mapping
- Need to maintain when struct changes
- More code to write and maintain

## Memory Allocation Breakdown

### JSON Approach (130 allocations):
- JSON marshaling: ~1 allocation
- JSON string storage: ~656 bytes
- JSON unmarshaling: ~129 allocations (one per field + map creation)
- Total memory: 5,228 bytes

### ToMap Approach (35 allocations):
- Map creation: ~1 allocation
- Field assignments: ~22 allocations (one per field)
- Nested maps (runtime, k8s): ~12 allocations
- Total memory: 3,112 bytes

## Real-World Impact

For a system processing **1,000 exec events per second**:

| Metric | JSON Approach | ToMap Approach | Improvement |
|--------|---------------|----------------|-------------|
| CPU Time/sec | 17.9 ms | 2.8 ms | **84% reduction** |
| Memory/sec | 5.2 MB | 3.1 MB | **40% reduction** |
| Allocations/sec | 130,000 | 35,000 | **73% reduction** |
| GC Pressure | High | Low | **Significant** |

## Recommendations

### Use Custom ToMap() when:
- High-frequency event processing
- Performance is critical
- Memory usage is a concern
- CPU resources are limited
- You need predictable performance

### Use JSON Marshal/Unmarshal when:
- Low-frequency operations
- Development speed is priority
- Struct changes frequently
- Code maintenance is a concern
- Performance is not critical

## Implementation Notes

The custom ToMap() method includes:
- All exec event fields (pid, tid, comm, args, etc.)
- CommonData fields (K8s metadata, runtime info)
- Proper handling of nested structures
- Conditional inclusion of optional fields

## Conclusion

**The custom ToMap() method provides significant performance benefits:**
- **6.4x faster execution**
- **40% less memory usage**  
- **73% fewer allocations**
- **Better scalability for high-throughput scenarios**

For production systems handling large volumes of exec events, the custom ToMap() approach is strongly recommended despite the additional maintenance overhead. 