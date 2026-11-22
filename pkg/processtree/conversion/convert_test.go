package conversion

import (
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertProcfsEvent_CarriesStartTime(t *testing.T) {
	wall := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	pe := &events.ProcfsEvent{
		Type: types.NORMAL, Timestamp: types.Time(time.Now().UnixNano()),
		PID: 42, PPID: 1, Comm: "nginx",
		StartTimeNs:   123_450_000_000, // 12345 ticks
		StartTimeWall: wall,
	}
	got, err := ConvertEvent(utils.ProcfsEventType, pe)
	require.NoError(t, err)
	assert.Equal(t, uint64(123_450_000_000), got.StartTimeNs)
	assert.Equal(t, wall, got.StartTimeWall)
}

func TestConvertEvent_ExecForkExitAndUnsupported(t *testing.T) {
	ev := &utils.StructEvent{
		Pid:         100,
		Ppid:        10,
		Comm:        "curl",
		Pcomm:       "sh",
		ExePath:     "/usr/bin/curl",
		Args:        []string{"curl", "-s", "https://example.com"},
		Uid:         1000,
		Gid:         1000,
		ContainerID: "cid-100",
		Timestamp:   555_000,
	}

	execGot, err := ConvertEvent(utils.ExecveEventType, ev)
	require.NoError(t, err)
	assert.Equal(t, ExecEvent, execGot.Type)
	assert.Equal(t, uint32(100), execGot.PID)
	assert.Equal(t, uint32(10), execGot.PPID)
	assert.Equal(t, "curl", execGot.Comm)
	assert.Equal(t, "sh", execGot.Pcomm)
	assert.Equal(t, "/usr/bin/curl", execGot.Path)
	assert.Equal(t, "curl -s https://example.com", execGot.Cmdline)
	assert.Equal(t, "cid-100", execGot.ContainerID)
	assert.Equal(t, uint64(555_000), execGot.StartTimeNs)
	require.NotNil(t, execGot.Uid)
	assert.Equal(t, uint32(1000), *execGot.Uid)
	require.NotNil(t, execGot.Gid)
	assert.Equal(t, uint32(1000), *execGot.Gid)

	forkGot, err := ConvertEvent(utils.ForkEventType, ev)
	require.NoError(t, err)
	assert.Equal(t, ForkEvent, forkGot.Type)
	assert.Equal(t, uint32(100), forkGot.PID)
	assert.Equal(t, "/usr/bin/curl", forkGot.Path)
	assert.Equal(t, "cid-100", forkGot.ContainerID)

	exitGot, err := ConvertEvent(utils.ExitEventType, ev)
	require.NoError(t, err)
	assert.Equal(t, ExitEvent, exitGot.Type)
	assert.Equal(t, uint32(100), exitGot.PID)
	assert.Equal(t, "cid-100", exitGot.ContainerID)

	_, err = ConvertEvent(utils.OpenEventType, ev)
	assert.Error(t, err)
}
