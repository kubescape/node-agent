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

type symlinkEvent struct {
	Timestamp  uint64
	MntnsId    uint64
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	UpperLayer bool
	Comm       [16]uint8
	Oldpath    [4096]uint8
	Newpath    [4096]uint8
	_          [7]byte
}

// loadSymlink returns the embedded CollectionSpec for symlink.
func loadSymlink() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SymlinkBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load symlink: %w", err)
	}

	return spec, err
}

// loadSymlinkObjects loads symlink and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*symlinkObjects
//	*symlinkPrograms
//	*symlinkMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSymlinkObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSymlink()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// symlinkSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type symlinkSpecs struct {
	symlinkProgramSpecs
	symlinkMapSpecs
}

// symlinkSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type symlinkProgramSpecs struct {
	TracepointSysSymlink   *ebpf.ProgramSpec `ebpf:"tracepoint__sys_symlink"`
	TracepointSysSymlinkat *ebpf.ProgramSpec `ebpf:"tracepoint__sys_symlinkat"`
}

// symlinkMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type symlinkMapSpecs struct {
	Bufs                 *ebpf.MapSpec `ebpf:"bufs"`
	EmptyEvent           *ebpf.MapSpec `ebpf:"empty_event"`
	Events               *ebpf.MapSpec `ebpf:"events"`
	GadgetHeap           *ebpf.MapSpec `ebpf:"gadget_heap"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
}

// symlinkObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSymlinkObjects or ebpf.CollectionSpec.LoadAndAssign.
type symlinkObjects struct {
	symlinkPrograms
	symlinkMaps
}

func (o *symlinkObjects) Close() error {
	return _SymlinkClose(
		&o.symlinkPrograms,
		&o.symlinkMaps,
	)
}

// symlinkMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSymlinkObjects or ebpf.CollectionSpec.LoadAndAssign.
type symlinkMaps struct {
	Bufs                 *ebpf.Map `ebpf:"bufs"`
	EmptyEvent           *ebpf.Map `ebpf:"empty_event"`
	Events               *ebpf.Map `ebpf:"events"`
	GadgetHeap           *ebpf.Map `ebpf:"gadget_heap"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
}

func (m *symlinkMaps) Close() error {
	return _SymlinkClose(
		m.Bufs,
		m.EmptyEvent,
		m.Events,
		m.GadgetHeap,
		m.GadgetMntnsFilterMap,
	)
}

// symlinkPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSymlinkObjects or ebpf.CollectionSpec.LoadAndAssign.
type symlinkPrograms struct {
	TracepointSysSymlink   *ebpf.Program `ebpf:"tracepoint__sys_symlink"`
	TracepointSysSymlinkat *ebpf.Program `ebpf:"tracepoint__sys_symlinkat"`
}

func (p *symlinkPrograms) Close() error {
	return _SymlinkClose(
		p.TracepointSysSymlink,
		p.TracepointSysSymlinkat,
	)
}

func _SymlinkClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed symlink_bpfel.o
var _SymlinkBytes []byte
