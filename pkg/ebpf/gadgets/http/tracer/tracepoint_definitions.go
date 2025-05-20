package tracer

import tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"

func GetTracepointDefinitions(objs *http_snifferPrograms) []tracepointlib.TracepointInfo {
	return []tracepointlib.TracepointInfo{
		{"sys_enter_read", objs.SysEnterRead},
		{"sys_exit_read", objs.SysExitRead},
		{"sys_enter_recvfrom", objs.SysEnterRecvfrom},
		{"sys_exit_recvfrom", objs.SysExitRecvfrom},
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
