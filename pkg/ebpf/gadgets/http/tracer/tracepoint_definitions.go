package tracer

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type TracepointInfo struct {
	Syscall string
	ObjFunc interface{}
}

func GetTracepointDefinitions(objs *http_snifferPrograms) []TracepointInfo {
	return []TracepointInfo{
		{"sys_enter_accept", objs.SysEnterAccept},
		{"sys_enter_accept4", objs.SysEnterAccept4},
		{"sys_exit_accept", objs.SysExitAccept},
		{"sys_exit_accept4", objs.SysExitAccept4},
		{"sys_enter_read", objs.SysEnterRead},
		{"sys_exit_read", objs.SysExitRead},
		{"sys_enter_close", objs.SysEnterClose},
		{"sys_enter_recvfrom", objs.SysEnterRecvfrom},
		{"sys_exit_recvfrom", objs.SysExitRecvfrom},
		{"sys_enter_connect", objs.SyscallProbeEntryConnect},
		{"sys_exit_connect", objs.SyscallProbeRetConnect},
		{"sys_enter_write", objs.SyscallProbeEntryWrite},
		{"sys_exit_write", objs.SyscallProbeRetWrite},
		{"sys_enter_sendto", objs.SyscallProbeEntrySendto},
		{"sys_exit_sendto", objs.SyscallProbeRetSendto},
		{"sys_enter_sendmsg", objs.SyscallProbeEntrySendmsg},
		{"sys_exit_sendmsg", objs.SyscallProbeRetSendmsg},
		{"sys_enter_recvmsg", objs.SyscallProbeEntryRecvmsg},
		{"sys_exit_recvmsg", objs.SyscallProbeRetRecvmsg},
		{"sys_enter_writev", objs.SyscallProbeEntryWritev},
		{"sys_exit_writev", objs.SyscallProbeRetWritev},
		{"sys_enter_readv", objs.SyscallProbeEntryReadv},
		{"sys_exit_readv", objs.SyscallProbeRetReadv},
	}
}

func AttachTracepoint(tracepoint TracepointInfo) (link.Link, error) {
	l, err := link.Tracepoint("syscalls", tracepoint.Syscall, tracepoint.ObjFunc.(*ebpf.Program), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracepoint %s: %v", tracepoint.Syscall, err)
	}
	return l, nil
}