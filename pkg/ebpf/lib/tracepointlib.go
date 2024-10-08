package tracepointlib

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type TracepointInfo struct {
	Syscall string
	ObjFunc interface{}
}

func AttachTracepoint(tracepoint TracepointInfo) (link.Link, error) {
	l, err := link.Tracepoint("syscalls", tracepoint.Syscall, tracepoint.ObjFunc.(*ebpf.Program), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracepoint %s: %v", tracepoint.Syscall, err)
	}
	return l, nil
}

func ConvertToEvent[T any](record *perf.Record) *T {
	return (*T)(unsafe.Pointer(&record.RawSample[0]))
}
