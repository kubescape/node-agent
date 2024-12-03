package ruleengine

import (
	"testing"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/stretchr/testify/assert"
)

func TestHandleExecveEvent(t *testing.T) {
	rule := &R1005FilelessExecution{}

	t.Run("Test with /proc/self/fd prefix", func(t *testing.T) {
		event := &tracerexectype.Event{
			Cwd:        "/proc/self/fd",
			UpperLayer: false,
			Ppid:       123,
			Pcomm:      "test",
			Comm:       "test",
			Gid:        123,
			Pid:        123,
			Uid:        123,
		}
		execEvent := events.ExecEvent{Event: *event}
		result := rule.handleExecveEvent(&execEvent)
		assert.NotNil(t, result)
	})

	t.Run("Test without /proc/self/fd prefix", func(t *testing.T) {
		event := &tracerexectype.Event{
			Cwd:        "/not/proc/self/fd",
			UpperLayer: false,
			Ppid:       123,
			Pcomm:      "test",
			Comm:       "test",
			Gid:        123,
			Pid:        123,
			Uid:        123,
		}

		execEvent := events.ExecEvent{Event: *event}
		result := rule.handleExecveEvent(&execEvent)
		assert.Nil(t, result)
	})

	t.Run("Test with relative path", func(t *testing.T) {
		event := &tracerexectype.Event{
			Cwd:        "./relative/path",
			UpperLayer: false,
			Ppid:       123,
			Pcomm:      "test",
			Comm:       "test",
			Gid:        123,
			Pid:        123,
			Uid:        123,
		}

		execEvent := events.ExecEvent{Event: *event}
		result := rule.handleExecveEvent(&execEvent)
		assert.Nil(t, result)
	})

	t.Run("Test with absolute path", func(t *testing.T) {
		event := &tracerexectype.Event{
			Cwd:        "/absolute/path",
			UpperLayer: false,
			Ppid:       123,
			Pcomm:      "test",
			Comm:       "test",
			Gid:        123,
			Pid:        123,
			Uid:        123,
		}

		execEvent := events.ExecEvent{Event: *event}
		result := rule.handleExecveEvent(&execEvent)
		assert.Nil(t, result)
	})
}
