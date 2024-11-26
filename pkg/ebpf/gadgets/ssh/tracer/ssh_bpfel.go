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

type sshEvent struct {
	Netns     uint32
	_         [4]byte
	Timestamp uint64
	MntnsId   uint64
	Pid       uint32
	Uid       uint32
	Gid       uint32
	DstPort   uint16
	SrcPort   uint16
	DstIp     uint32
	SrcIp     uint32
	Comm      [16]uint8
}

// loadSsh returns the embedded CollectionSpec for ssh.
func loadSsh() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SshBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load ssh: %w", err)
	}

	return spec, err
}

// loadSshObjects loads ssh and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*sshObjects
//	*sshPrograms
//	*sshMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSshObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSsh()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sshSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sshSpecs struct {
	sshProgramSpecs
	sshMapSpecs
}

// sshSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sshProgramSpecs struct {
	SshDetector *ebpf.ProgramSpec `ebpf:"ssh_detector"`
}

// sshMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sshMapSpecs struct {
	EmptyEvent    *ebpf.MapSpec `ebpf:"empty_event"`
	Events        *ebpf.MapSpec `ebpf:"events"`
	GadgetHeap    *ebpf.MapSpec `ebpf:"gadget_heap"`
	GadgetSockets *ebpf.MapSpec `ebpf:"gadget_sockets"`
}

// sshObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSshObjects or ebpf.CollectionSpec.LoadAndAssign.
type sshObjects struct {
	sshPrograms
	sshMaps
}

func (o *sshObjects) Close() error {
	return _SshClose(
		&o.sshPrograms,
		&o.sshMaps,
	)
}

// sshMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSshObjects or ebpf.CollectionSpec.LoadAndAssign.
type sshMaps struct {
	EmptyEvent    *ebpf.Map `ebpf:"empty_event"`
	Events        *ebpf.Map `ebpf:"events"`
	GadgetHeap    *ebpf.Map `ebpf:"gadget_heap"`
	GadgetSockets *ebpf.Map `ebpf:"gadget_sockets"`
}

func (m *sshMaps) Close() error {
	return _SshClose(
		m.EmptyEvent,
		m.Events,
		m.GadgetHeap,
		m.GadgetSockets,
	)
}

// sshPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSshObjects or ebpf.CollectionSpec.LoadAndAssign.
type sshPrograms struct {
	SshDetector *ebpf.Program `ebpf:"ssh_detector"`
}

func (p *sshPrograms) Close() error {
	return _SshClose(
		p.SshDetector,
	)
}

func _SshClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed ssh_bpfel.o
var _SshBytes []byte
