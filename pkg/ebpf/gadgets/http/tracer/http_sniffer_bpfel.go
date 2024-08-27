// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type http_snifferActiveConnectionInfo struct {
	Sockfd int32
	Addr   struct {
		SinFamily uint16
		SinPort   uint16
		SinAddr   struct{ S_addr uint32 }
		Pad       [8]uint8
	}
}

type http_snifferDebugEvent struct {
	Sockfd uint32
	Addr   struct {
		SinFamily uint16
		SinPort   uint16
		SinAddr   struct{ S_addr uint32 }
		Pad       [8]uint8
	}
	Message [64]int8
}

type http_snifferHttpevent struct {
	Netns     uint32
	_         [4]byte
	Timestamp uint64
	MntnsId   uint64
	Pid       uint32
	Uid       uint32
	Gid       uint32
	Type      uint8
	_         [3]byte
	SockFd    uint32
	Buf       [1028]uint8
	Syscall   [128]uint8
	OtherIp   uint32
	OtherPort uint16
	_         [2]byte
}

type http_snifferPacketBuffer struct {
	Sockfd int32
	_      [4]byte
	Buf    uint64
	Len    uint64
}

// loadHttp_sniffer returns the embedded CollectionSpec for http_sniffer.
func loadHttp_sniffer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Http_snifferBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load http_sniffer: %w", err)
	}

	return spec, err
}

// loadHttp_snifferObjects loads http_sniffer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*http_snifferObjects
//	*http_snifferPrograms
//	*http_snifferMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHttp_snifferObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHttp_sniffer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// http_snifferSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type http_snifferSpecs struct {
	http_snifferProgramSpecs
	http_snifferMapSpecs
}

// http_snifferSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type http_snifferProgramSpecs struct {
	SysEnterAccept           *ebpf.ProgramSpec `ebpf:"sys_enter_accept"`
	SysEnterAccept4          *ebpf.ProgramSpec `ebpf:"sys_enter_accept4"`
	SysEnterClose            *ebpf.ProgramSpec `ebpf:"sys_enter_close"`
	SysEnterRead             *ebpf.ProgramSpec `ebpf:"sys_enter_read"`
	SysEnterRecvfrom         *ebpf.ProgramSpec `ebpf:"sys_enter_recvfrom"`
	SysExitAccept            *ebpf.ProgramSpec `ebpf:"sys_exit_accept"`
	SysExitAccept4           *ebpf.ProgramSpec `ebpf:"sys_exit_accept4"`
	SysExitRead              *ebpf.ProgramSpec `ebpf:"sys_exit_read"`
	SysExitRecvfrom          *ebpf.ProgramSpec `ebpf:"sys_exit_recvfrom"`
	SyscallProbeEntryConnect *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_connect"`
	SyscallProbeEntryReadv   *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_readv"`
	SyscallProbeEntryRecvmsg *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_recvmsg"`
	SyscallProbeEntrySendmsg *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_sendmsg"`
	SyscallProbeEntrySendto  *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_sendto"`
	SyscallProbeEntryWrite   *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_write"`
	SyscallProbeEntryWritev  *ebpf.ProgramSpec `ebpf:"syscall__probe_entry_writev"`
	SyscallProbeRetConnect   *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_connect"`
	SyscallProbeRetReadv     *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_readv"`
	SyscallProbeRetRecvmsg   *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_recvmsg"`
	SyscallProbeRetSendmsg   *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_sendmsg"`
	SyscallProbeRetSendto    *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_sendto"`
	SyscallProbeRetWrite     *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_write"`
	SyscallProbeRetWritev    *ebpf.ProgramSpec `ebpf:"syscall__probe_ret_writev"`
}

// http_snifferMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type http_snifferMapSpecs struct {
	AcceptedSocketsMap       *ebpf.MapSpec `ebpf:"accepted_sockets_map"`
	ActiveConnectionsArgsMap *ebpf.MapSpec `ebpf:"active_connections_args_map"`
	BufferPackets            *ebpf.MapSpec `ebpf:"buffer_packets"`
	DebugEvents              *ebpf.MapSpec `ebpf:"debug_events"`
	EmptyChar                *ebpf.MapSpec `ebpf:"empty_char"`
	EventData                *ebpf.MapSpec `ebpf:"event_data"`
	Events                   *ebpf.MapSpec `ebpf:"events"`
	GadgetSockets            *ebpf.MapSpec `ebpf:"gadget_sockets"`
	MsgPackets               *ebpf.MapSpec `ebpf:"msg_packets"`
	PreAcceptArgsMap         *ebpf.MapSpec `ebpf:"pre_accept_args_map"`
}

// http_snifferObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHttp_snifferObjects or ebpf.CollectionSpec.LoadAndAssign.
type http_snifferObjects struct {
	http_snifferPrograms
	http_snifferMaps
}

func (o *http_snifferObjects) Close() error {
	return _Http_snifferClose(
		&o.http_snifferPrograms,
		&o.http_snifferMaps,
	)
}

// http_snifferMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHttp_snifferObjects or ebpf.CollectionSpec.LoadAndAssign.
type http_snifferMaps struct {
	AcceptedSocketsMap       *ebpf.Map `ebpf:"accepted_sockets_map"`
	ActiveConnectionsArgsMap *ebpf.Map `ebpf:"active_connections_args_map"`
	BufferPackets            *ebpf.Map `ebpf:"buffer_packets"`
	DebugEvents              *ebpf.Map `ebpf:"debug_events"`
	EmptyChar                *ebpf.Map `ebpf:"empty_char"`
	EventData                *ebpf.Map `ebpf:"event_data"`
	Events                   *ebpf.Map `ebpf:"events"`
	GadgetSockets            *ebpf.Map `ebpf:"gadget_sockets"`
	MsgPackets               *ebpf.Map `ebpf:"msg_packets"`
	PreAcceptArgsMap         *ebpf.Map `ebpf:"pre_accept_args_map"`
}

func (m *http_snifferMaps) Close() error {
	return _Http_snifferClose(
		m.AcceptedSocketsMap,
		m.ActiveConnectionsArgsMap,
		m.BufferPackets,
		m.DebugEvents,
		m.EmptyChar,
		m.EventData,
		m.Events,
		m.GadgetSockets,
		m.MsgPackets,
		m.PreAcceptArgsMap,
	)
}

// http_snifferPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHttp_snifferObjects or ebpf.CollectionSpec.LoadAndAssign.
type http_snifferPrograms struct {
	SysEnterAccept           *ebpf.Program `ebpf:"sys_enter_accept"`
	SysEnterAccept4          *ebpf.Program `ebpf:"sys_enter_accept4"`
	SysEnterClose            *ebpf.Program `ebpf:"sys_enter_close"`
	SysEnterRead             *ebpf.Program `ebpf:"sys_enter_read"`
	SysEnterRecvfrom         *ebpf.Program `ebpf:"sys_enter_recvfrom"`
	SysExitAccept            *ebpf.Program `ebpf:"sys_exit_accept"`
	SysExitAccept4           *ebpf.Program `ebpf:"sys_exit_accept4"`
	SysExitRead              *ebpf.Program `ebpf:"sys_exit_read"`
	SysExitRecvfrom          *ebpf.Program `ebpf:"sys_exit_recvfrom"`
	SyscallProbeEntryConnect *ebpf.Program `ebpf:"syscall__probe_entry_connect"`
	SyscallProbeEntryReadv   *ebpf.Program `ebpf:"syscall__probe_entry_readv"`
	SyscallProbeEntryRecvmsg *ebpf.Program `ebpf:"syscall__probe_entry_recvmsg"`
	SyscallProbeEntrySendmsg *ebpf.Program `ebpf:"syscall__probe_entry_sendmsg"`
	SyscallProbeEntrySendto  *ebpf.Program `ebpf:"syscall__probe_entry_sendto"`
	SyscallProbeEntryWrite   *ebpf.Program `ebpf:"syscall__probe_entry_write"`
	SyscallProbeEntryWritev  *ebpf.Program `ebpf:"syscall__probe_entry_writev"`
	SyscallProbeRetConnect   *ebpf.Program `ebpf:"syscall__probe_ret_connect"`
	SyscallProbeRetReadv     *ebpf.Program `ebpf:"syscall__probe_ret_readv"`
	SyscallProbeRetRecvmsg   *ebpf.Program `ebpf:"syscall__probe_ret_recvmsg"`
	SyscallProbeRetSendmsg   *ebpf.Program `ebpf:"syscall__probe_ret_sendmsg"`
	SyscallProbeRetSendto    *ebpf.Program `ebpf:"syscall__probe_ret_sendto"`
	SyscallProbeRetWrite     *ebpf.Program `ebpf:"syscall__probe_ret_write"`
	SyscallProbeRetWritev    *ebpf.Program `ebpf:"syscall__probe_ret_writev"`
}

func (p *http_snifferPrograms) Close() error {
	return _Http_snifferClose(
		p.SysEnterAccept,
		p.SysEnterAccept4,
		p.SysEnterClose,
		p.SysEnterRead,
		p.SysEnterRecvfrom,
		p.SysExitAccept,
		p.SysExitAccept4,
		p.SysExitRead,
		p.SysExitRecvfrom,
		p.SyscallProbeEntryConnect,
		p.SyscallProbeEntryReadv,
		p.SyscallProbeEntryRecvmsg,
		p.SyscallProbeEntrySendmsg,
		p.SyscallProbeEntrySendto,
		p.SyscallProbeEntryWrite,
		p.SyscallProbeEntryWritev,
		p.SyscallProbeRetConnect,
		p.SyscallProbeRetReadv,
		p.SyscallProbeRetRecvmsg,
		p.SyscallProbeRetSendmsg,
		p.SyscallProbeRetSendto,
		p.SyscallProbeRetWrite,
		p.SyscallProbeRetWritev,
	)
}

func _Http_snifferClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed http_sniffer_bpfel.o
var _Http_snifferBytes []byte
