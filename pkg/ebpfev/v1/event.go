package ebpfev

import (
	"sniffer/pkg/config"
	"sniffer/pkg/utils"
	"strings"
	"time"
)

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

func CreateKernelEvent(timestamp *time.Time, containerID string, syscallOp string, ppid string, pid string, syscallArgs string, exe string, cmd string) *EventData {
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

func (ev *EventData) GetOpenFileName() string {
	fileName := ""
	if config.GetConfigurationConfigContext().IsFalcoEbpfEngine() {
		switch ev.syscallOp {
		case "CAT=PROCESS":
			if strings.HasPrefix(ev.syscallArgs, "TYPE=execve(") {
				fileName = utils.Between(ev.syscallArgs, "filename: ", ")")
			} else if strings.HasPrefix(ev.syscallArgs, "TYPE=execveat(") {
				fileName = utils.Between(ev.syscallArgs, "dirfd: <f>", ", pathname:")
			}
		case "CAT=FILE":
			if strings.HasPrefix(ev.syscallArgs, "TYPE=openat(") {
				fileName = utils.Between(ev.syscallArgs, "name: ", ", flags")
			} else if strings.HasPrefix(ev.syscallArgs, "TYPE=open(") {
				fileName = utils.Between(ev.syscallArgs, "name: ", ", flags")
			}
		}
	} else {
		fileName = ev.syscallArgs
	}
	return fileName
}
