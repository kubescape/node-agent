package processtreecreator

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	processtreecreatorconfig "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleProcfsEvent_RecordsStartTime(t *testing.T) {
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, config.Config{})
	wall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, Timestamp: time.Now(),
		PID: 100, PPID: 1, Comm: "nginx",
		StartTimeNs: 555_550_000_000, StartTimeWall: wall,
	})

	// Boot-ns identity: exposed via the accessor, sourced from the side map.
	assert.Equal(t, uint64(555_550_000_000), creator.GetProcessBootTimeNs(100))
	assert.Zero(t, creator.GetProcessBootTimeNs(999), "unknown pid reads as 0")

	// Wall-clock display value on the node.
	node, err := creator.GetProcessNode(100)
	require.NoError(t, err)
	require.NotNil(t, node)
	assert.Equal(t, wall, node.StartTime)
}

func TestExitByPid_DeletesStartTimeEntry(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 10, CleanupInterval: time.Hour, CleanupDelay: 0,
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)
	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ProcfsEvent, PID: 100, PPID: 1, Comm: "nginx",
		StartTimeNs: 1_000_000_000,
	})
	require.Equal(t, uint64(1_000_000_000), creator.GetProcessBootTimeNs(100),
		"precondition: the side map must hold the entry before the exit")

	creator.FeedEvent(conversion.ProcessEvent{
		Type: conversion.ExitEvent, PID: 100, Comm: "exit", Timestamp: time.Now(),
	})
	creator.mutex.Lock()
	creator.exitByPid(100)
	creator.mutex.Unlock()

	assert.Zero(t, creator.GetProcessBootTimeNs(100), "side-map entry must die with the node")
}

// TestExitByPid_DeletesStartTimeEntry_NodeAlreadyGone covers exitByPid's early
// return: the node is absent from processMap, but a stale side-map entry must
// still be reclaimed rather than leaking for the lifetime of the agent.
func TestExitByPid_DeletesStartTimeEntry_NodeAlreadyGone(t *testing.T) {
	cfg := config.Config{}
	cfg.ExitCleanup = processtreecreatorconfig.ExitCleanupConfig{
		MaxPendingExits: 10, CleanupInterval: time.Hour, CleanupDelay: 0,
	}
	creator := NewProcessTreeCreator(&mockContainerProcessTree{}, cfg).(*processTreeCreatorImpl)

	creator.mutex.Lock()
	creator.pidStartTimeNs[404] = 2_000_000_000 // entry with no corresponding node
	creator.exitByPid(404)
	creator.mutex.Unlock()

	assert.Zero(t, creator.GetProcessBootTimeNs(404),
		"the early-return branch must reclaim the side-map entry too")
}
