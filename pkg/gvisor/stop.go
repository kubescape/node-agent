package gvisor

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// MESSAGE_SENTRY_EXIT_NOTIFY_PARENT and MESSAGE_SENTRY_TASK_EXIT in gVisor's
	// common.proto. Both carry ContextData (field 1) and a wait-style int32
	// exit_status (field 2) in sentry.proto, checked against release-20261019.0.
	exitNotifyParentMessage = 4
	taskExitMessage         = 5

	// maxTrackedPerConnection bounds the stop state kept for one trace
	// connection (one sandbox). Starts beyond it are counted, not tracked.
	maxTrackedPerConnection = 1024
)

// Stop is the entire retained terminal event. Like Start, it carries no argv,
// cwd, environment, credentials, process name or raw protobuf bytes.
type Stop struct {
	Source      string
	ContainerID string
	ObservedAt  time.Time
	Dropped     uint32 // Cumulative sender-reported drop count on this connection.
	ExitCode    int    // CRI-style: the exit code, or 128+signal when signaled.
	Signal      int    // Terminating signal, or zero for a normal exit.
}

// StopHandler receives stops for containers whose start was runtime-verified
// on the same connection. It must honor ctx cancellation.
type StopHandler func(context.Context, Stop)

// taskKey identifies a container's initial task inside one sandbox. Thread
// group IDs repeat across sandboxes and can be reused within one, so the
// group's start time is part of the key.
type taskKey struct {
	group      int32
	groupStart int64
}

func (k taskKey) valid() bool { return k.group > 0 && k.groupStart > 0 }

type exitFrame struct {
	task    taskContext
	status  int32
	dropped uint32
}

// decodeExitFrame returns ok=false for message types other than task exit and
// parent notification. Only the task context and exit status are retained.
func decodeExitFrame(frame []byte) (exitFrame, bool, error) {
	if len(frame) < headerSize {
		return exitFrame{}, false, errors.New("short remote sink header")
	}
	length := int(binary.LittleEndian.Uint16(frame[:2]))
	if length < headerSize || length > len(frame) {
		return exitFrame{}, false, errors.New("invalid remote sink header size")
	}
	kind := binary.LittleEndian.Uint16(frame[2:4])
	if kind != taskExitMessage && kind != exitNotifyParentMessage {
		return exitFrame{}, false, nil
	}
	exit := exitFrame{dropped: binary.LittleEndian.Uint32(frame[4:8])}
	payload := frame[length:]
	for len(payload) > 0 {
		number, wire, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return exitFrame{}, false, errors.New("invalid exit tag")
		}
		payload = payload[n:]
		switch {
		case number == 1 && wire == protowire.BytesType:
			value, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 {
				return exitFrame{}, false, errors.New("invalid exit context")
			}
			task, err := decodeTaskContext(value)
			if err != nil {
				return exitFrame{}, false, err
			}
			exit.task = task
			payload = payload[consumed:]
		case number == 2 && wire == protowire.VarintType:
			value, consumed := protowire.ConsumeVarint(payload)
			if consumed < 0 {
				return exitFrame{}, false, errors.New("invalid exit status")
			}
			exit.status = int32(value) // int32 varints are sign-extended on the wire.
			payload = payload[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(number, wire, payload)
			if consumed < 0 {
				return exitFrame{}, false, errors.New("invalid exit field")
			}
			payload = payload[consumed:]
		}
	}
	return exit, true, nil
}

// exitCode maps a wait(2) status to the code CRI reports. Stopped/continued
// statuses and negative values are not terminations and are rejected.
func exitCode(status int32) (code, signal int, ok bool) {
	if status < 0 {
		return 0, 0, false
	}
	switch sig := int(status & 0x7f); sig {
	case 0:
		return int(status>>8) & 0xff, 0, true
	case 0x7f:
		return 0, 0, false
	default:
		return 128 + sig, sig, true
	}
}

type terminalResult int

const (
	nonterminal terminalResult = iota // not the tracked initial task
	firstTerminal
	duplicateTerminal // the second point for an already reported termination
	invalidTerminal   // tracked initial task, but an unusable exit status
)

type trackedTask struct {
	key     taskKey
	stopped bool
}

// stopTracker holds verified initial tasks for one connection. It is used only
// from that connection's receive goroutine, so it needs no locking. A sandbox
// teardown, an unresolved claim, a child or exec task, another thread of the
// group, or a reused group ID with a different start time never matches.
type stopTracker struct {
	tasks map[string]trackedTask
}

func newStopTracker() *stopTracker { return &stopTracker{tasks: map[string]trackedTask{}} }

// track records a verified start. It returns false when the per-connection
// bound is reached; that container's stop will then not be observed.
func (t *stopTracker) track(containerID string, key taskKey) bool {
	if _, exists := t.tasks[containerID]; !exists && len(t.tasks) >= maxTrackedPerConnection {
		return false
	}
	t.tasks[containerID] = trackedTask{key: key}
	return true
}

func (t *stopTracker) observe(exit exitFrame) (terminalResult, int, int) {
	tracked, ok := t.tasks[exit.task.containerID]
	if !ok || exit.task.thread != exit.task.group || exit.task.key() != tracked.key {
		return nonterminal, 0, 0
	}
	if tracked.stopped {
		// Both exit points report the same termination: forget the task now.
		delete(t.tasks, exit.task.containerID)
		return duplicateTerminal, 0, 0
	}
	code, signal, valid := exitCode(exit.status)
	if !valid {
		return invalidTerminal, 0, 0
	}
	tracked.stopped = true
	t.tasks[exit.task.containerID] = tracked
	return firstTerminal, code, signal
}

// unobserved counts tracked containers whose termination this connection did
// not report. Their stops are left to the runtime, not inferred from closure.
func (t *stopTracker) unobserved() uint64 {
	var n uint64
	for _, task := range t.tasks {
		if !task.stopped {
			n++
		}
	}
	return n
}
