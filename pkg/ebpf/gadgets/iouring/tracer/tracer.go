package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -strip /usr/bin/llvm-strip-18 -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" -type event iouring bpf/iouring.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)
	objs          iouringObjects
	links         []link.Link
	reader        *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event)) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.Close()
		return nil, err
	}

	go t.run()
	return t, nil
}

func (t *Tracer) Close() {
	for _, l := range t.links {
		gadgets.CloseLink(l)
	}
	if t.reader != nil {
		t.reader.Close()
	}
	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadIouring()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	tracepoint, err := link.Tracepoint("io_uring", "io_uring_submit_sqe", t.objs.TraceIoUringSubmit, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.links = append(t.links, tracepoint)

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
			t.eventCallback(&types.Event{Event: eventtypes.Err(msg)})
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(&types.Event{Event: eventtypes.Warn(msg)})
			continue
		}

		bpfEvent := tracepointlib.ConvertToEvent[iouringEvent](&record)
		t.eventCallback(t.parseEvent(bpfEvent))
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.Close()

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
		panic("invalid event handler type")
	}
	t.eventCallback = nh
}

func (t *Tracer) parseEvent(bpfEvent *iouringEvent) *types.Event {
	return &types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		Opcode:        bpfEvent.Opcode,
		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Comm:          gadgets.FromCString(*(*[]byte)(unsafe.Pointer(&bpfEvent.Comm))),
		Flags:         bpfEvent.Flags,
		UserData:      bpfEvent.UserData,
	}
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
