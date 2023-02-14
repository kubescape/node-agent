package ebpfev

import "time"

type EventData struct {
	timestamp   time.Time
	containerID string
	ppid        string
	pid         string
	syscallOp   string
	syscallArgs string
	exe         string
	cmd         string
}

func CreateKernelEvent(timestamp *time.Time, containerID string, ppid string, pid string, syscallOp string, syscallArgs string, exe string, cmd string) *EventData {
	return &EventData{
		timestamp:   *timestamp,
		containerID: containerID,
		ppid:        ppid,
		pid:         pid,
		syscallOp:   syscallOp,
		syscallArgs: syscallArgs,
		exe:         exe,
		cmd:         cmd,
	}
}

func (ev *EventData) GetEventTimestamp() time.Time {
	return ev.timestamp
}
func (ev *EventData) GetEventContainerID() string {
	return ev.containerID
}
func (ev *EventData) GetEventPPID() string {
	return ev.ppid
}
func (ev *EventData) GetEventPID() string {
	return ev.pid
}
func (ev *EventData) GetEventSyscallOp() string {
	return ev.syscallOp
}
func (ev *EventData) GetEventSyscallArgs() string {
	return ev.syscallArgs
}
func (ev *EventData) GetEventEXE() string {
	return ev.exe
}
func (ev *EventData) GetEventCMD() string {
	return ev.cmd
}
