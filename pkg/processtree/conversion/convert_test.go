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
