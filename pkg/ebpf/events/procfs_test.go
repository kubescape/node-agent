package events

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestProcfsEvent_Methods(t *testing.T) {
	ev := &ProcfsEvent{
		Type:        types.NORMAL,
		Timestamp:   types.Time(123456789),
		PID:         100,
		PPID:        1,
		Comm:        "nginx",
		ContainerID: "container-xyz",
	}

	assert.Equal(t, "container-xyz", ev.GetContainerID())
	assert.Equal(t, utils.ProcfsEventType, ev.GetEventType())
	assert.Equal(t, types.NORMAL, ev.GetType())
	assert.Equal(t, types.Time(123456789), ev.GetTimestamp())
	assert.Equal(t, "", ev.GetNamespace())
	assert.Equal(t, "", ev.GetPod())
	assert.False(t, ev.HasDroppedEvents())
	assert.NotPanics(t, func() {
		ev.Release()
	})
}
