package utils

type RuntimeK8sEvent interface {
	GetNamespace() string
	GetPod() string
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
	AllEventType          EventType = "all"
)
