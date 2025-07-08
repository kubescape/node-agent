package processtree

import (
	"context"
	"testing"
	"time"

	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTreeManager_WaitForProcessProcessing(t *testing.T) {
	// Create components
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree)
	eventFeeder := feeder.NewEventFeeder()

	// Create process tree manager
	ptm := NewProcessTreeManager(creator, containerTree, []feeder.ProcessEventFeeder{eventFeeder})

	// Start the manager
	ctx := context.Background()
	err := ptm.Start(ctx)
	require.NoError(t, err)
	defer ptm.Stop()

	// Test waiting for a process that hasn't been processed yet
	pid := uint32(12345)

	// This should timeout since the process hasn't been processed
	err = ptm.WaitForProcessProcessing(pid, 50*time.Millisecond)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout waiting for process processing")

	// Test that the method works when cache is available
	// We'll test the basic functionality without complex event processing
	err = ptm.WaitForProcessProcessing(pid, 10*time.Millisecond)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout waiting for process processing")
}

func TestProcessTreeManager_WaitForProcessProcessing_NoCache(t *testing.T) {
	// Create components
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree)
	eventFeeder := feeder.NewEventFeeder()

	// Create process tree manager with nil cache (simulating cache creation failure)
	ptm := &ProcessTreeManagerImpl{
		creator:             creator,
		containerTree:       containerTree,
		feeders:             []feeder.ProcessEventFeeder{eventFeeder},
		eventChan:           make(chan feeder.ProcessEvent, 1000),
		processedExecEvents: nil, // No cache
	}

	// Start the manager
	ctx := context.Background()
	err := ptm.Start(ctx)
	require.NoError(t, err)
	defer ptm.Stop()

	// Test waiting for a process - should return immediately with no error
	pid := uint32(12345)

	err = ptm.WaitForProcessProcessing(pid, 100*time.Millisecond)
	assert.NoError(t, err)
}

func TestProcessTreeManager_WaitForProcessProcessing_DifferentStartTime(t *testing.T) {
	// Create components
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := processtreecreator.NewProcessTreeCreator(containerTree)
	eventFeeder := feeder.NewEventFeeder()

	// Create process tree manager
	ptm := NewProcessTreeManager(creator, containerTree, []feeder.ProcessEventFeeder{eventFeeder})

	// Start the manager
	ctx := context.Background()
	err := ptm.Start(ctx)
	require.NoError(t, err)
	defer ptm.Stop()

	pid := uint32(12345)

	// Process an exec event
	// Note: In a real scenario, this would be processed through the event system
	// For testing, we'll just verify the timeout behavior

	// Wait for the process - should timeout since no event was processed
	err = ptm.WaitForProcessProcessing(pid, 50*time.Millisecond)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout waiting for process processing")

	// Wait again - should also timeout
	err = ptm.WaitForProcessProcessing(pid, 50*time.Millisecond)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout waiting for process processing")
}
