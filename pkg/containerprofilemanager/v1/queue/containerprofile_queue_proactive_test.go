package queue

import (
	"context"
	"fmt"
	"testing"

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
	admitted := make(chan bool, 1)
	go func() {
		close(started)
		admitted <- qd.requeueSplit(&QueuedContainerProfile{Profile: parent}, a, b, false)
	}()
	<-started
	incoming := testProfile()
	err = qd.enqueueLocked(&QueuedContainerProfile{Profile: incoming, ContainerID: "incoming"})
	qd.mu.Unlock()
	require.NoError(t, err)
	require.False(t, <-admitted)
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
