package tracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type event ssh bpf/ssh.bpf.c -- -I./bpf/ -I /usr/include/x86_64-linux-gnu -D__x86_64__

type Tracer struct {
	*networktracer.Tracer[types.Event]

	cancel context.CancelFunc
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

func (t *Tracer) Close() {
	if t.cancel != nil {
		t.cancel()
	}

	if t.Tracer != nil {
		t.Tracer.Close()
	}
}

func (t *Tracer) install() error {
	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}
	t.Tracer = networkTracer
	return nil
}

func (t *Tracer) RunWorkaround() error {
	if err := t.run(); err != nil {
		t.Close()
		return fmt.Errorf("running tracer: %w", err)
	}
	return nil
}

func (t *Tracer) run() error {
	spec, err := loadSsh()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := t.Tracer.Run(spec, types.Base, t.parseSSH); err != nil {
		return fmt.Errorf("setting network tracer spec: %w", err)
	}

	return nil
}

func (t *Tracer) parseSSH(rawSample []byte, netns uint64) (*types.Event, error) {
	bpfEvent := (*sshEvent)(unsafe.Pointer(&rawSample[0]))

	srcIP := [4]byte{}
	binary.BigEndian.PutUint32(srcIP[:], bpfEvent.SrcIp)
	src := netip.AddrFrom4(srcIP).String()
	dstIP := [4]byte{}
	binary.BigEndian.PutUint32(dstIP[:], bpfEvent.DstIp)
	dst := netip.AddrFrom4(dstIP).String()
	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		SrcIP:         src,
		DstIP:         dst,
		SrcPort:       bpfEvent.SrcPort,
		DstPort:       bpfEvent.DstPort,
		Pid:           bpfEvent.Pid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
	}

	return &event, nil
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{}
	return tracer, nil
}
