package processtreecreator

import (
	"fmt"
	"sync"
	"testing"
	"time"

	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
)

// BenchmarkProcessTreeCreator_FeedEvents benchmarks the performance of feeding events
func BenchmarkProcessTreeCreator_FeedEvents(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i + 1),
			PPID:        uint32(i),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}
}

// BenchmarkProcessTreeCreator_GetProcessMap benchmarks the performance of getting process map
func BenchmarkProcessTreeCreator_GetProcessMap(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with some processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pt.GetProcessMap()
	}
}

// BenchmarkProcessTreeCreator_GetProcessMapDeep benchmarks the performance of getting deep copy process map
func BenchmarkProcessTreeCreator_GetProcessMapDeep(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with some processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pt.GetProcessMapDeep()
	}
}

// BenchmarkProcessTreeCreator_GetRootTree benchmarks the performance of getting root tree
func BenchmarkProcessTreeCreator_GetRootTree(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with some processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = pt.GetRootTree()
	}
}

// BenchmarkProcessTreeCreator_GetProcessNode benchmarks the performance of getting a single process node
func BenchmarkProcessTreeCreator_GetProcessNode(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with some processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = pt.GetProcessNode(500) // Get middle process
	}
}

// BenchmarkProcessTreeCreator_ConcurrentFeedEvents benchmarks concurrent event feeding
func BenchmarkProcessTreeCreator_ConcurrentFeedEvents(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pt.FeedEvent(feeder.ProcessEvent{
				Type:        feeder.ForkEvent,
				PID:         uint32(i + 1),
				PPID:        uint32(i),
				Comm:        fmt.Sprintf("proc-%d", i),
				StartTimeNs: uint64(time.Now().UnixNano()),
			})
			i++
		}
	})
}

// BenchmarkProcessTreeCreator_ConcurrentReads benchmarks concurrent read operations
func BenchmarkProcessTreeCreator_ConcurrentReads(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with some processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 4 {
			case 0:
				_ = pt.GetProcessMap()
			case 1:
				_, _ = pt.GetRootTree()
			case 2:
				_, _ = pt.GetProcessNode(500)
			case 3:
				_ = pt.GetProcessMapDeep()
			}
			i++
		}
	})
}

// BenchmarkProcessTreeCreator_MixedOperations benchmarks mixed read/write operations
func BenchmarkProcessTreeCreator_MixedOperations(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// 70% reads, 30% writes
			if i%10 < 7 {
				// Read operations
				switch i % 4 {
				case 0:
					_ = pt.GetProcessMap()
				case 1:
					_, _ = pt.GetRootTree()
				case 2:
					_, _ = pt.GetProcessNode(500)
				case 3:
					_ = pt.GetProcessMapDeep()
				}
			} else {
				// Write operations
				pt.FeedEvent(feeder.ProcessEvent{
					Type:        feeder.ForkEvent,
					PID:         uint32(i + 10000), // Use high PIDs to avoid conflicts
					PPID:        uint32(i + 9999),
					Comm:        fmt.Sprintf("proc-%d", i),
					StartTimeNs: uint64(time.Now().UnixNano()),
				})
			}
			i++
		}
	})
}

// BenchmarkProcessTreeCreator_LargeTree benchmarks performance with large process trees
func BenchmarkProcessTreeCreator_LargeTree(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Create a large tree with 10,000 processes
	numProcesses := 10000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pt.GetProcessMap()
	}
}

// BenchmarkProcessTreeCreator_DeepTree benchmarks performance with deep process trees
func BenchmarkProcessTreeCreator_DeepTree(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Create a deep tree (chain of processes)
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1), // Each process is child of previous
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = pt.GetRootTree()
	}
}

// BenchmarkProcessTreeCreator_BroadTree benchmarks performance with broad process trees
func BenchmarkProcessTreeCreator_BroadTree(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Create a broad tree (many children per parent)
	numParents := 100
	childrenPerParent := 50

	// Create parents
	for i := 1; i <= numParents; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        0, // Root processes
			Comm:        fmt.Sprintf("parent-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	// Create children
	for parent := 1; parent <= numParents; parent++ {
		for child := 1; child <= childrenPerParent; child++ {
			childPID := uint32(parent*1000 + child)
			pt.FeedEvent(feeder.ProcessEvent{
				Type:        feeder.ForkEvent,
				PID:         childPID,
				PPID:        uint32(parent),
				Comm:        fmt.Sprintf("child-%d-%d", parent, child),
				StartTimeNs: uint64(time.Now().UnixNano()),
			})
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = pt.GetRootTree()
	}
}

// BenchmarkProcessTreeCreator_ExitCleanup benchmarks the performance of exit cleanup
func BenchmarkProcessTreeCreator_ExitCleanup(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with processes that have children
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		// Create parent
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        0,
			Comm:        fmt.Sprintf("parent-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})

		// Create child
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i * 1000),
			PPID:        uint32(i),
			Comm:        fmt.Sprintf("child-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Trigger exit for a parent process
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ExitEvent,
			PID:         uint32(i%numProcesses + 1),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}
}

// BenchmarkProcessTreeCreator_ContainerTreeChecks benchmarks container tree checks
func BenchmarkProcessTreeCreator_ContainerTreeChecks(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// This will trigger container tree checks
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ExecEvent,
			PID:         uint32(i%numProcesses + 1),
			PPID:        uint32(i % numProcesses),
			Comm:        fmt.Sprintf("exec-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}
}

// BenchmarkProcessTreeCreator_MemoryUsage benchmarks memory usage patterns
func BenchmarkProcessTreeCreator_MemoryUsage(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	b.ResetTimer()
	b.ReportAllocs()

	// Simulate realistic usage pattern
	for i := 0; i < b.N; i++ {
		// Add some processes
		for j := 0; j < 100; j++ {
			pt.FeedEvent(feeder.ProcessEvent{
				Type:        feeder.ForkEvent,
				PID:         uint32(i*1000 + j + 1),
				PPID:        uint32(i*1000 + j),
				Comm:        fmt.Sprintf("proc-%d-%d", i, j),
				StartTimeNs: uint64(time.Now().UnixNano()),
			})
		}

		// Read operations
		_ = pt.GetProcessMap()
		_, _ = pt.GetRootTree()

		// Exit some processes
		for j := 0; j < 10; j++ {
			pt.FeedEvent(feeder.ProcessEvent{
				Type:        feeder.ExitEvent,
				PID:         uint32(i*1000 + j + 1),
				StartTimeNs: uint64(time.Now().UnixNano()),
			})
		}
	}
}

// BenchmarkProcessTreeCreator_ShallowVsDeepCopy compares shallow vs deep copy performance
func BenchmarkProcessTreeCreator_ShallowVsDeepCopy(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with a complex tree
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.Run("ShallowCopy", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pt.GetProcessMap()
		}
	})

	b.Run("DeepCopy", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pt.GetProcessMapDeep()
		}
	})
}

// BenchmarkProcessTreeCreator_ConcurrentAccessPatterns benchmarks realistic concurrent access patterns
func BenchmarkProcessTreeCreator_ConcurrentAccessPatterns(b *testing.B) {
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt := NewProcessTreeCreator(containerTree)

	// Pre-populate with processes
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type:        feeder.ForkEvent,
			PID:         uint32(i),
			PPID:        uint32(i - 1),
			Comm:        fmt.Sprintf("proc-%d", i),
			StartTimeNs: uint64(time.Now().UnixNano()),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	var wg sync.WaitGroup
	numReaders := 4
	numWriters := 1

	// Start readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < b.N/numReaders; i++ {
				_ = pt.GetProcessMap()
				_, _ = pt.GetRootTree()
				_, _ = pt.GetProcessNode(500)
			}
		}()
	}

	// Start writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < b.N/numWriters; i++ {
				pt.FeedEvent(feeder.ProcessEvent{
					Type:        feeder.ForkEvent,
					PID:         uint32(i + 10000),
					PPID:        uint32(i + 9999),
					Comm:        fmt.Sprintf("new-proc-%d", i),
					StartTimeNs: uint64(time.Now().UnixNano()),
				})
			}
		}()
	}

	wg.Wait()
}
