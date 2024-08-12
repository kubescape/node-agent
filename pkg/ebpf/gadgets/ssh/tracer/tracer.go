package tracer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type event ssh bpf/ssh.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	netEnricher   gadgets.DataEnricherByNetNs
	eventCallback func(*types.Event)

	objs sshObjects

	file   int
	reader *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
	netEnricher gadgets.DataEnricherByNetNs,
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		netEnricher:   netEnricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	if t.file != 0 {
		syscall.Close(t.file)
		t.file = 0
	}

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadSsh()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	// Open raw socket
	rawSockFd, err := rawsock.OpenRawSock(1)
	if err != nil {
		logger.L().Error("Error opening raw socket", helpers.Error(err))
	}

	// Attach BPF program to raw socket
	if err := syscall.SetsockoptInt(rawSockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, t.objs.SshDetector.FD()); err != nil {
		logger.L().Error("Error attaching BPF program to raw socket", helpers.Error(err))
	}

	// Store the file for later cleanup
	t.file = rawSockFd

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	return nil
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*sshEvent)(unsafe.Pointer(&record.RawSample[0]))

		srcIP := make(net.IP, 4)
		dstIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(srcIP, bpfEvent.SrcIp)
		binary.BigEndian.PutUint32(dstIP, bpfEvent.DstIp)

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(bpfEvent.Netns)},
			SrcIP:         srcIP.String(),
			DstIP:         dstIP.String(),
			SrcPort:       bpfEvent.SrcPort,
			DstPort:       bpfEvent.DstPort,
			Pid:           bpfEvent.Pid,
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
			t.netEnricher.EnrichByNetNs(&event.CommonData, event.NetNsID)
		}

		logger.L().Info("SSH event", helpers.Interface("event", event))

		t.eventCallback(&event)
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

// // Helper function to convert host byte order to network byte order
// func htons(host uint16) uint16 {
// 	return (host&0xff)<<8 | (host&0xff00)>>8
// }
