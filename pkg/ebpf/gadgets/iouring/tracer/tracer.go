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
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"
	kernel "github.com/kubescape/node-agent/pkg/validator/ebpf"
	"github.com/shirou/gopsutil/v4/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -strip /usr/bin/llvm-strip-18 -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" -type event iouring bpf/iouring.c -- -I./bpf/

const (
	SupportedMajor = 6
	SupportedMinor = 3
)

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
	fmt.Println("Installed")

	go t.run()
	fmt.Printf("Running")
	return t, nil
}

func (t *Tracer) Close() {
	fmt.Println("Closingggg")
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

	info, err := host.Info()
	if err != nil {
		return fmt.Errorf("failed to get host info: %w", err)
	}

	var tracepointName string
	major, minor, _, err := kernel.ParseKernelVersion(info.KernelVersion)
	if err != nil {
		return fmt.Errorf("parsing kernel version: %w", err)
	}

	if major >= SupportedMajor && minor >= SupportedMinor {
		tracepointName = "io_uring_submit_req"
	} else {
		tracepointName = "io_uring_submit_sqe"
	}

	tracepoint, err := link.Tracepoint("io_uring", tracepointName, t.objs.HandleSubmitReq, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint %s: %w", tracepointName, err)
	}

	t.links = append(t.links, tracepoint)

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		fmt.Println("Error creating perf ring buffer")
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	fmt.Println("All good")

	return nil
}

func (t *Tracer) run() {
	var readerMu sync.Mutex
	for {
		readerMu.Lock()
		if t.reader == nil {
			fmt.Println("WHAYYYYYYYYYY")
			readerMu.Unlock()
			return
		}

		record, err := t.reader.Read()
		readerMu.Unlock()
		if err != nil {
			fmt.Println("Fuckkkkkkkkkkkkkkkkkkk")
			fmt.Println("err", err)
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

		fmt.Println("record.LostSamples", record.LostSamples)

		bpfEvent := tracepointlib.ConvertToEvent[iouringEvent](&record)
		fmt.Println("bpfEvent", bpfEvent)
		t.eventCallback(t.parseEvent(bpfEvent))
		fmt.Println("t.parseEvent(bpfEvent)", t.parseEvent(bpfEvent))
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
	comm := gadgets.FromCString(*(*[]byte)(unsafe.Pointer(&bpfEvent.Comm)))
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
		Comm:          comm,
		Flags:         bpfEvent.Flags,
		UserData:      bpfEvent.UserData,
		Identifier:    fmt.Sprintf("%s-%d", comm, bpfEvent.Opcode),
	}
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

func (t *Tracer) Stop() {
	t.Close()
}
