// Code generated by bpf2go; DO NOT EDIT.

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type randomxEvent struct {
	Timestamp uint64
	MntnsId   uint64
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	Gid       uint32
	Comm      [16]uint8
}

// loadRandomx returns the embedded CollectionSpec for randomx.
func loadRandomx() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_RandomxBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load randomx: %w", err)
	}

	return spec, err
}

// loadRandomxObjects loads randomx and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*randomxObjects
//	*randomxPrograms
//	*randomxMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadRandomxObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadRandomx()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// randomxSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type randomxSpecs struct {
	randomxProgramSpecs
	randomxMapSpecs
}

// randomxSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type randomxProgramSpecs struct {
	TracepointX86FpuRegsDeactivated *ebpf.ProgramSpec `ebpf:"tracepoint__x86_fpu_regs_deactivated"`
}

// randomxMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type randomxMapSpecs struct {
	Events               *ebpf.MapSpec `ebpf:"events"`
	GadgetHeap           *ebpf.MapSpec `ebpf:"gadget_heap"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
}

// randomxObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadRandomxObjects or ebpf.CollectionSpec.LoadAndAssign.
type randomxObjects struct {
	randomxPrograms
	randomxMaps
}

func (o *randomxObjects) Close() error {
	return _RandomxClose(
		&o.randomxPrograms,
		&o.randomxMaps,
	)
}

// randomxMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadRandomxObjects or ebpf.CollectionSpec.LoadAndAssign.
type randomxMaps struct {
	Events               *ebpf.Map `ebpf:"events"`
	GadgetHeap           *ebpf.Map `ebpf:"gadget_heap"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
}

func (m *randomxMaps) Close() error {
	return _RandomxClose(
		m.Events,
		m.GadgetHeap,
		m.GadgetMntnsFilterMap,
	)
}

// randomxPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadRandomxObjects or ebpf.CollectionSpec.LoadAndAssign.
type randomxPrograms struct {
	TracepointX86FpuRegsDeactivated *ebpf.Program `ebpf:"tracepoint__x86_fpu_regs_deactivated"`
}

func (p *randomxPrograms) Close() error {
	return _RandomxClose(
		p.TracepointX86FpuRegsDeactivated,
	)
}

func _RandomxClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed randomx_bpf.o
var _RandomxBytes []byte
