package queue

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProactiveSplitPreservesFullQueue verifies that optional splitting never evicts
// pending data when dequeuing the original freed only one slot.
func TestProactiveSplitPreservesFullQueue(t *testing.T) {
	for _, capacity := range []int{1, 3} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			creator := &MockProfileCreator{}
			qd, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: capacity})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, qd.Close()) })

			parent := testProfile()
			parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
			_, _, ok := splitProfile(parent)
			require.True(t, ok)
			require.NoError(t, qd.EnqueueWithSizeLimit(parent, "parent", 1))
			for i := 1; i < capacity; i++ {
				pending := testProfile()
				pending.Name = fmt.Sprintf("pending-%d", i)
				pending.Spec.Capabilities = []string{"pending-capability"}
				require.NoError(t, qd.Enqueue(pending, pending.Name))
			}

			qd.processAllItems()

			created := creator.CreatedProfiles()
			require.Len(t, created, capacity)
			assert.Equal(t, parent, created[0], "capacity pressure must send the intact original")
			for i := 1; i < capacity; i++ {
				assert.Equal(t, fmt.Sprintf("pending-%d", i), created[i].Name)
				assert.Equal(t, []string{"pending-capability"}, created[i].Spec.Capabilities)
			}
			assert.Zero(t, qd.splits.Load())
			assert.Zero(t, qd.chunksDropped.Load())
			assert.Zero(t, qd.GetQueueSize())
		})
	}
}

// TestProactiveSplitChecksCapacityAtAdmission verifies that a producer consuming
// capacity before split admission cannot cause the split to evict pending data.
func TestProactiveSplitChecksCapacityAtAdmission(t *testing.T) {
	qd, err := NewQueueData(context.Background(), &MockProfileCreator{}, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: 3})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, qd.Close()) })
	parent := testProfile()
	parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
	a, b, ok := splitProfile(parent)
	require.True(t, ok)
	pending := testProfile()
	require.NoError(t, qd.Enqueue(pending, "pending"))
	require.Equal(t, 2, qd.maxQueueSize-qd.GetQueueSize())

	// A producer holds the admission lock while the split waits. Its enqueue uses
	// the same locked path as Enqueue and consumes one of the two available slots.
	qd.mu.Lock()
	started := make(chan struct{})
	fallback := make(chan *QueuedContainerProfile, 1)
	go func() {
		close(started)
		fallback <- qd.requeueSplit(&QueuedContainerProfile{Profile: parent}, a, b, false)
	}()
	<-started
	incoming := testProfile()
	err = qd.enqueueLocked(&QueuedContainerProfile{Profile: incoming, ContainerID: "incoming"})
	qd.mu.Unlock()
	require.NoError(t, err)
	unsent := <-fallback
	require.NotNil(t, unsent)
	require.Same(t, parent, unsent.Profile)
	assert.Zero(t, qd.chunksDropped.Load())
	require.Equal(t, 2, qd.GetQueueSize())
	for _, id := range []string{"pending", "incoming"} {
		item, err := qd.queue.Dequeue()
		require.NoError(t, err)
		assert.Equal(t, id, item.(*QueuedContainerProfile).ContainerID)
	}
}

// TestProactiveSplitUsesAvailableCapacity verifies that both halves are delivered
// when proactive splitting has enough queue capacity.
func TestProactiveSplitUsesAvailableCapacity(t *testing.T) {
	creator := &MockProfileCreator{}
	qd, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, qd.Close()) })
	parent := testProfile()
	parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
	require.NoError(t, qd.EnqueueWithSizeLimit(parent, "parent", 1))
	qd.processAllItems()
	assert.Empty(t, creator.CreatedProfiles())
	assert.Equal(t, int64(1), qd.splits.Load())
	require.Equal(t, 2, qd.GetQueueSize())
	qd.processAllItems()
	created := creator.CreatedProfiles()
	require.Len(t, created, 2)
	assert.Equal(t, parent.Spec.Capabilities, append(created[0].Spec.Capabilities, created[1].Spec.Capabilities...))
	assert.Zero(t, qd.chunksDropped.Load())
	assert.Zero(t, qd.GetQueueSize())
}

// TestProactiveSplitSendsOriginalDuringShutdown verifies that stopping queue admission
// while processing is in flight preserves the original payload for its direct send.
func TestProactiveSplitSendsOriginalDuringShutdown(t *testing.T) {
	for _, capacity := range []int{1, 2} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			creator := &MockProfileCreator{}
			qd, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxQueueSize: capacity})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, qd.Close()) })
			parent := testProfile()
			parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
			_, _, ok := splitProfile(parent)
			require.True(t, ok)
			require.NoError(t, qd.EnqueueWithSizeLimit(parent, "parent", 1))

			// Close disables admission before waiting for the processor to finish.
			// Reproduce that state without closing the disk queue underneath processing.
			qd.mu.Lock()
			qd.running = false
			qd.mu.Unlock()
			qd.processAllItems()

			created := creator.CreatedProfiles()
			require.Len(t, created, 1)
			assert.Equal(t, parent, created[0])
			assert.Zero(t, qd.splits.Load())
			assert.Zero(t, qd.chunksDropped.Load())
			assert.Zero(t, qd.GetQueueSize())
		})
	}
}

// recoveringDiskCreator restores segment creation when storage receives a profile,
// allowing each regression to verify the complete delivery after an enqueue failure.
type recoveringDiskCreator struct {
	MockProfileCreator
	blockedSegment string
}

// CreateContainerProfileDirect clears the injected disk failure and records delivery.
func (c *recoveringDiskCreator) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	if c.blockedSegment != "" {
		if err := os.Remove(c.blockedSegment); err != nil {
			return err
		}
		c.blockedSegment = ""
	}
	return c.MockProfileCreator.CreateContainerProfileDirect(profile)
}

// TestProactiveSplitPreservesDataOnDiskFailure verifies that optional splitting sends
// the original on first-half failure and only the unqueued half on second-half failure.
func TestProactiveSplitPreservesDataOnDiskFailure(t *testing.T) {
	for _, itemsPerSegment := range []int{2, 3} {
		t.Run(fmt.Sprint(itemsPerSegment), func(t *testing.T) {
			dir := t.TempDir()
			creator := &recoveringDiskCreator{}
			qd, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: dir, MaxQueueSize: 4, ItemsPerSegment: itemsPerSegment})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, qd.Close()) })
			parent := testProfile()
			parent.Spec.Capabilities = []string{"cap-a", "cap-b"}
			require.NoError(t, qd.EnqueueWithSizeLimit(parent, "parent", 1))
			pending := testProfile()
			pending.Name = "pending"
			require.NoError(t, qd.Enqueue(pending, "pending"))

			// dque starts at segment 1. Keep a pending item there so dequeuing the
			// parent does not rotate segments. Two slots force the first-half enqueue
			// to create segment 2; three slots defer that failure to the second half.
			blocked := filepath.Join(dir, DefaultQueueName, "0000000000002.dque")
			require.NoError(t, os.Mkdir(blocked, 0700))
			creator.blockedSegment = blocked
			qd.processAllItems()
			require.Empty(t, creator.blockedSegment, "fallback must reach storage before pending data is dequeued")
			qd.processAllItems()

			created := creator.CreatedProfiles()
			if itemsPerSegment == 2 {
				require.Len(t, created, 2)
				assert.Equal(t, parent, created[0])
				assert.Zero(t, qd.splits.Load())
			} else {
				require.Len(t, created, 3)
				// The second half is sent immediately; the first remains queued until
				// the next processing pass. Their payloads and chain still cover parent.
				a, b := created[2], created[0]
				assert.Equal(t, parent.Spec.Capabilities, append(a.Spec.Capabilities, b.Spec.Capabilities...))
				assert.Equal(t, parent.Annotations[helpersv1.PreviousReportTimestampMetadataKey], a.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
				assert.Equal(t, a.Annotations[helpersv1.ReportTimestampMetadataKey], b.Annotations[helpersv1.PreviousReportTimestampMetadataKey])
				assert.Equal(t, parent.Annotations[helpersv1.ReportTimestampMetadataKey], b.Annotations[helpersv1.ReportTimestampMetadataKey])
				assert.Equal(t, int64(1), qd.splits.Load())
			}
			assert.Equal(t, pending, created[1])
			assert.Zero(t, qd.chunksDropped.Load())
			assert.Zero(t, qd.GetQueueSize())
		})
	}
}

// finalDepthCreator records requests while applying a protobuf payload size limit.
type finalDepthCreator struct {
	byteLimitedCreator
	attempted []*v1beta1.ContainerProfile
}

// CreateContainerProfileDirect records the attempted payload before applying storage's cap.
func (c *finalDepthCreator) CreateContainerProfileDirect(profile *v1beta1.ContainerProfile) error {
	c.attempted = append(c.attempted, profile.DeepCopy())
	return c.byteLimitedCreator.CreateContainerProfileDirect(profile)
}

// TestProactiveSplitReservesFinalDepth verifies storage sees a still-acceptable parent
// before a final optional split can grow its protobuf payload through timestamp metadata.
func TestProactiveSplitReservesFinalDepth(t *testing.T) {
	for _, maxDepth := range []int{1, DefaultMaxSplitDepth} {
		for _, requiresSplit := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth=%d/requiresSplit=%t", maxDepth, requiresSplit), func(t *testing.T) {
				parent := testProfile()
				parent.Annotations[helpersv1.PreviousReportTimestampMetadataKey] = "2026-10-05 10:59:59.99975 +0000 UTC"
				parent.Annotations[helpersv1.ReportTimestampMetadataKey] = "2026-10-05 11:00:00 +0000 UTC"
				if requiresSplit {
					parent.Spec.Ingress = []v1beta1.NetworkNeighbor{portSplitNeighbor()}
				} else {
					parent.Spec.Opens = []v1beta1.OpenCalls{{Path: "/a"}}
					parent.Spec.Syscalls = []string{"poll"}
				}
				a, b, ok := splitProfile(parent)
				require.True(t, ok)
				creator := &finalDepthCreator{byteLimitedCreator: byteLimitedCreator{limit: parent.Size()}}
				if requiresSplit {
					creator.limit = max(a.Size(), b.Size())
					require.Less(t, creator.limit, parent.Size())
				} else {
					require.Greater(t, max(a.Size(), b.Size()), parent.Size(), "JSON progress can still enlarge protobuf metadata")
				}
				q, err := NewQueueData(context.Background(), creator, QueueConfig{QueueDir: t.TempDir(), MaxSplitDepth: maxDepth})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, q.Close()) })
				q.mu.Lock()
				err = q.enqueueLocked(&QueuedContainerProfile{Profile: parent, ContainerID: "container", SplitDepth: maxDepth - 1, MaxProfileSize: 1})
				q.mu.Unlock()
				require.NoError(t, err)
				for range 3 {
					q.processAllItems()
				}
				require.NotEmpty(t, creator.attempted)
				require.Equal(t, parent, creator.attempted[0], "the final split level must first try storage")
				var observations []string
				var rows []tsRow
				for _, accepted := range creator.accepted {
					observations = append(observations, elementSignatures(&accepted.Spec)...)
					rows = append(rows, tsRow{PreviousReportTimestamp: accepted.Annotations[helpersv1.PreviousReportTimestampMetadataKey], ReportTimestamp: accepted.Annotations[helpersv1.ReportTimestampMetadataKey]})
				}
				require.ElementsMatch(t, elementSignatures(&parent.Spec), observations)
				assertChainIsLinear(t, rows, parent.Annotations[helpersv1.PreviousReportTimestampMetadataKey], parent.Annotations[helpersv1.ReportTimestampMetadataKey])
				require.Zero(t, q.chunksDropped.Load())
				require.Zero(t, q.GetQueueSize())
				if requiresSplit {
					require.Equal(t, int64(1), q.splits.Load(), "HTTP 413 retains the final split level")
				} else {
					require.Zero(t, q.splits.Load())
				}
			})
		}
	}
}
