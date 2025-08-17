package tracer

import tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"

func GetTracepointDefinitions(objs *http_snifferPrograms) []tracepointlib.TracepointInfo {
	return []tracepointlib.TracepointInfo{
		{Syscall: "sys_enter_read", ObjFunc: objs.SysEnterRead},
		{Syscall: "sys_exit_read", ObjFunc: objs.SysExitRead},
		{Syscall: "sys_enter_recvfrom", ObjFunc: objs.SysEnterRecvfrom},
		{Syscall: "sys_exit_recvfrom", ObjFunc: objs.SysExitRecvfrom},
		{Syscall: "sys_enter_write", ObjFunc: objs.SyscallProbeEntryWrite},
		{Syscall: "sys_exit_write", ObjFunc: objs.SyscallProbeRetWrite},
		{Syscall: "sys_enter_sendto", ObjFunc: objs.SyscallProbeEntrySendto},
		{Syscall: "sys_exit_sendto", ObjFunc: objs.SyscallProbeRetSendto},
		{Syscall: "sys_enter_sendmsg", ObjFunc: objs.SyscallProbeEntrySendmsg},
		{Syscall: "sys_exit_sendmsg", ObjFunc: objs.SyscallProbeRetSendmsg},
		{Syscall: "sys_enter_recvmsg", ObjFunc: objs.SyscallProbeEntryRecvmsg},
		{Syscall: "sys_exit_recvmsg", ObjFunc: objs.SyscallProbeRetRecvmsg},
		{Syscall: "sys_enter_writev", ObjFunc: objs.SyscallProbeEntryWritev},
		{Syscall: "sys_exit_writev", ObjFunc: objs.SyscallProbeRetWritev},
		{Syscall: "sys_enter_readv", ObjFunc: objs.SyscallProbeEntryReadv},
		{Syscall: "sys_exit_readv", ObjFunc: objs.SyscallProbeRetReadv},
	}
}
