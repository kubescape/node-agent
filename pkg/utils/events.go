package utils

import "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

type K8sEvent interface {
	GetPod() string
	GetNamespace() string
}

type EnrichEvent interface {
	GetBaseEvent() *types.Event
	GetPID() int
	SetExtra(extra interface{})
}

type EventType string

const (
	ExecveEventType       EventType = "exec"
	OpenEventType         EventType = "open"
	CapabilitiesEventType EventType = "capabilities"
	DnsEventType          EventType = "dns"
	NetworkEventType      EventType = "network"
	SyscallEventType      EventType = "syscall"
	RandomXEventType      EventType = "randomx"
	SymlinkEventType      EventType = "symlink"
	HardlinkEventType     EventType = "hardlink"
	SSHEventType          EventType = "ssh"
	HTTPEventType         EventType = "http"
	PtraceEventType       EventType = "ptrace"
	AllEventType          EventType = "all"
)
