package gvisor

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func varintField(number protowire.Number, value uint64) []byte {
	field := protowire.AppendTag(nil, number, protowire.VarintType)
	return protowire.AppendVarint(field, value)
}

// taskContextBytes builds ContextData with the fields the stop path reads,
// plus cwd and process name, which must never be retained.
func taskContextBytes(id string, thread, group int32, groupStart int64, canary string) []byte {
	payload := varintField(1, 100)
	payload = append(payload, varintField(2, uint64(thread))...)
	payload = append(payload, varintField(3, uint64(groupStart))...)
	payload = append(payload, varintField(4, uint64(group))...)
	payload = append(payload, varintField(5, uint64(groupStart))...)
	payload = append(payload, bytesField(6, []byte(id))...)
	payload = append(payload, bytesField(8, []byte("/work/"+canary))...)
	return append(payload, bytesField(9, []byte(canary))...)
}

func header(message uint16, dropped uint32) []byte {
	frame := make([]byte, headerSize)
	binary.LittleEndian.PutUint16(frame[:2], headerSize)
	binary.LittleEndian.PutUint16(frame[2:4], message)
	binary.LittleEndian.PutUint32(frame[4:8], dropped)
	return frame
}

func keyedStartFrame(id string, group int32, groupStart int64, canary string) []byte {
	payload := bytesField(1, taskContextBytes(id, group, group, groupStart, canary))
	payload = append(payload, bytesField(2, []byte(id))...)
	payload = append(payload, bytesField(4, []byte("--token="+canary))...)
	return append(header(startMessage, 0), payload...)
}

func exitFrameBytes(message uint16, id string, thread, group int32, groupStart int64, status int32) []byte {
	payload := bytesField(1, taskContextBytes(id, thread, group, groupStart, "exit-canary"))
	payload = append(payload, varintField(2, uint64(int64(status)))...)
	return append(header(message, 2), payload...)
}

func TestStartRetainsInitialTaskKey(t *testing.T) {
	start, ok, err := decodeStartFrame(keyedStartFrame("c1", 2, 555, "canary"), time.Now(), func(string) bool { return true })
	if err != nil || !ok || start.key != (taskKey{group: 2, groupStart: 555}) {
		t.Fatalf("start key: %+v ok=%t err=%v", start.key, ok, err)
	}
	encoded, _ := json.Marshal(start)
	if strings.Contains(string(encoded), "canary") || strings.Contains(string(encoded), "555") {
		t.Fatalf("start leaked private or sandbox-local fields: %s", encoded)
	}
	// Older trace configurations omit the start time; the start still works,
	// but the container cannot be matched to a stop.
	old, ok, err := decodeStartFrame(startFrame("c1", "c1", "canary"), time.Now(), func(string) bool { return true })
	if err != nil || !ok || old.key.valid() {
		t.Fatalf("start without key: %+v ok=%t err=%v", old.key, ok, err)
	}
}

func TestExitFrameDecodesOnlyContextAndStatus(t *testing.T) {
	exit, ok, err := decodeExitFrame(exitFrameBytes(taskExitMessage, "c1", 2, 2, 555, 7<<8))
	if err != nil || !ok {
		t.Fatalf("exit: ok=%t err=%v", ok, err)
	}
	if exit.task != (taskContext{containerID: "c1", thread: 2, group: 2, groupStart: 555}) || exit.status != 1792 || exit.dropped != 2 {
		t.Fatalf("unexpected exit: %+v", exit)
	}
	negative, _, err := decodeExitFrame(exitFrameBytes(exitNotifyParentMessage, "c1", 2, 2, 555, -1))
	if err != nil || negative.status != -1 {
		t.Fatalf("negative int32 status: %d err=%v", negative.status, err)
	}
	if _, ok, err := decodeExitFrame(startFrame("c1", "c1", "x")); ok || err != nil {
		t.Fatalf("start decoded as exit: ok=%t err=%v", ok, err)
	}
	if _, _, err := decodeExitFrame(append(exitFrameBytes(taskExitMessage, "c1", 2, 2, 555, 0), 0xff)); err == nil {
		t.Fatal("malformed exit accepted")
	}
	if _, _, err := decodeExitFrame(exitFrameBytes(taskExitMessage, strings.Repeat("a", maxIDSize+1), 2, 2, 1, 0)); err == nil {
		t.Fatal("oversized exit ID accepted")
	}
}

func TestExitCodeMatchesCRI(t *testing.T) {
	// Values observed in the #1091 trial against CRI exit codes.
	for _, tc := range []struct {
		status       int32
		code, signal int
	}{{7 << 8, 7, 0}, {5 << 8, 5, 0}, {0, 0, 0}, {15, 143, 15}, {9, 137, 9}, {24 << 8, 24, 0}} {
		code, signal, ok := exitCode(tc.status)
		if !ok || code != tc.code || signal != tc.signal {
			t.Fatalf("status %d: code=%d signal=%d ok=%t", tc.status, code, signal, ok)
		}
	}
	for _, status := range []int32{-1, 0x137f, 0xffff} {
		if _, _, ok := exitCode(status); ok {
			t.Fatalf("non-terminal status %#x accepted", status)
		}
	}
}

func exit(id string, thread, group int32, groupStart int64, status int32) exitFrame {
	return exitFrame{task: taskContext{containerID: id, thread: thread, group: group, groupStart: groupStart}, status: status}
}

func TestTrackerMatchesOnlyTheInitialTask(t *testing.T) {
	tracker := newStopTracker()
	tracker.track("app", taskKey{group: 2, groupStart: 100})
	tracker.track("second", taskKey{group: 3, groupStart: 300})

	for name, e := range map[string]exitFrame{
		"child or exec task":          exit("app", 3, 3, 150, 4<<8),
		"other thread of the group":   exit("app", 5, 2, 100, 0),
		"reused group, new start":     exit("app", 2, 2, 999, 0),
		"same group in other sandbox": exit("other", 2, 2, 100, 0),
		"unresolved pause container":  exit("sandbox", 1, 1, 50, 9),
	} {
		if result, _, _ := tracker.observe(e); result != nonterminal {
			t.Fatalf("%s matched: %v", name, result)
		}
	}
	if result, code, signal := tracker.observe(exit("app", 2, 2, 100, 15)); result != firstTerminal || code != 143 || signal != 15 {
		t.Fatalf("init exit: result=%v code=%d signal=%d", result, code, signal)
	}
	// The parent notification for the same termination is not a second stop.
	if result, _, _ := tracker.observe(exit("app", 2, 2, 100, 15)); result != duplicateTerminal {
		t.Fatalf("duplicate point: %v", result)
	}
	// An orphaned child exiting after the init task is still not a stop.
	if result, _, _ := tracker.observe(exit("app", 3, 3, 150, 9)); result != nonterminal {
		t.Fatalf("late child exit: %v", result)
	}
	if got := tracker.unobserved(); got != 1 {
		t.Fatalf("second container should remain unobserved, got %d", got)
	}
	if result, code, _ := tracker.observe(exit("second", 3, 3, 300, 12<<8)); result != firstTerminal || code != 12 {
		t.Fatalf("second container in the same sandbox: %v %d", result, code)
	}
	if got := tracker.unobserved(); got != 0 {
		t.Fatalf("unobserved after both stops: %d", got)
	}
	if result, _, _ := tracker.observe(exit("second", 3, 3, 300, 0x137f)); result != duplicateTerminal {
		t.Fatalf("duplicate after stop: %v", result)
	}
}

func TestTrackerRejectsUnusableStatusAndBoundsState(t *testing.T) {
	tracker := newStopTracker()
	tracker.track("app", taskKey{group: 2, groupStart: 100})
	if result, _, _ := tracker.observe(exit("app", 2, 2, 100, 0x137f)); result != invalidTerminal {
		t.Fatalf("stopped status treated as exit: %v", result)
	}
	if result, _, _ := tracker.observe(exit("app", 2, 2, 100, 0)); result != firstTerminal {
		t.Fatalf("valid exit after invalid status: %v", result)
	}
	full := newStopTracker()
	for i := range maxTrackedPerConnection {
		if !full.track(strings.Repeat("x", i+1), taskKey{group: 2, groupStart: 1}) {
			t.Fatal("tracker refused below its bound")
		}
	}
	if full.track("overflow", taskKey{group: 2, groupStart: 1}) {
		t.Fatal("tracker exceeded its bound")
	}
	if full.unobserved() != maxTrackedPerConnection {
		t.Fatal("tracked tasks not counted as unobserved")
	}
}
