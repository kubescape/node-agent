package tracer

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	ebpfgadgets "github.com/kubescape/node-agent/pkg/ebpf/gadgets"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	kernel "github.com/kubescape/node-agent/pkg/validator/ebpf"
	"github.com/shirou/gopsutil/v4/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -strip /usr/bin/llvm-strip-18 -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall -DVERSION_63=1" -type event iouring_63 bpf/iouring.c -- -I./bpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -strip /usr/bin/llvm-strip-18 -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type event iouring bpf/iouring.c -- -I./bpf/

const (
	SupportedMajor = 6
	SupportedMinor = 3
)

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config *Config
	//enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)
	objs          iouringObjects
	links         []link.Link
	reader        *perf.Reader

	// recordPool will pool perf.Record objects to avoid allocations.
	recordPool sync.Pool
}

func NewTracer(config *Config, //enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event)) (*Tracer, error) {
	t := &Tracer{
		config: config,
		//enricher:      enricher,
		eventCallback: eventCallback,
	}

	t.recordPool.New = func() any {
		return new(perf.Record)
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
	if t.objs.Events != nil {
		t.objs.Close()
	}
}

func (t *Tracer) install() error {
	//var spec *ebpf.CollectionSpec
	var tracepointName string

	info, err := host.Info()
	if err != nil {
		return fmt.Errorf("failed to get host info: %w", err)
	}

	major, minor, _, err := kernel.ParseKernelVersion(info.KernelVersion)
	if err != nil {
		return fmt.Errorf("parsing kernel version: %w", err)
	}
	if major >= SupportedMajor && minor >= SupportedMinor {
		//spec, err = loadIouring_63()
		//if err != nil {
		//	return fmt.Errorf("loading ebpf program: %w", err)
		//}
		tracepointName = "io_uring_submit_req"

	} else {
		//spec, err = loadIouring()
		//if err != nil {
		//	return fmt.Errorf("loading ebpf program: %w", err)
		//}
		tracepointName = "io_uring_submit_sqe"
	}

	//if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
	//	return fmt.Errorf("loading ebpf spec: %w", err)
	//}

	tracepoint, err := link.Tracepoint("io_uring", tracepointName, t.objs.HandleSubmitReq, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint %s: %w", tracepointName, err)
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
		record := t.recordPool.Get().(*perf.Record)
		err := t.reader.ReadInto(record)
		if err != nil {
			t.recordPool.Put(record)
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			//msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			//t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			//msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			//t.eventCallback(types.Base(eventtypes.Warn(msg)))
			t.recordPool.Put(record)
			continue
		}

		if len(record.RawSample) == 0 {
			t.recordPool.Put(record)
			continue
		}

		bpfEvent := (*iouringEvent)(unsafe.Pointer(&record.RawSample[0]))
		event := t.parseEvent(bpfEvent)
		//if t.enricher != nil {
		//	t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		//}
		t.eventCallback(event)
		t.recordPool.Put(record)
	}

}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
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
		//Event: eventtypes.Event{
		//	Type:      eventtypes.NORMAL,
		//	Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		//},
		//WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		Pid:        bpfEvent.Pid,
		Tid:        bpfEvent.Tid,
		Uid:        bpfEvent.Uid,
		Gid:        bpfEvent.Gid,
		Opcode:     bpfEvent.Opcode,
		Flags:      bpfEvent.Flags,
		Comm:       gadgets.FromCString(bpfEvent.Comm[:]),
		Identifier: fmt.Sprintf("%s-%d", gadgets.FromCString(bpfEvent.Comm[:]), bpfEvent.Opcode),
	}
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (ebpfgadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

func (t *Tracer) Stop() {
	t.Close()
}
