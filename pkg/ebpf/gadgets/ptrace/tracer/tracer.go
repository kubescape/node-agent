package tracer

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -strip /usr/bin/llvm-strip-18 -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" -type event ptrace bpf/ptrace_detector.c -- -I./bpf/
const (
	EVENT_TYPE_CONNECT = iota
	EVENT_TYPE_ACCEPT
	EVENT_TYPE_REQUEST
	EVENT_TYPE_RESPONSE
	EVENT_TYPE_CLOSE
)

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs ptraceObjects

	ptracelinks []link.Link
	reader      *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
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
	for _, l := range t.ptracelinks {
		gadgets.CloseLink(l)
	}

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()

}

func (t *Tracer) install() error {
	var err error
	spec, err := loadPtrace()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	var links []link.Link
	tp := tracepointlib.TracepointInfo{Syscall: "sys_enter_ptrace", ObjFunc: t.objs.ptracePrograms.TraceEnterPtrace}
	l, err := tracepointlib.AttachTracepoint(tp)
	if err != nil {
		logger.L().Fatal("ptrace Tracer - error attaching tracepoint", helpers.Error(err))
	}
	links = append(links, l)

	t.ptracelinks = links

	t.reader, err = perf.NewReader(t.objs.ptraceMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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
				// nothing to do, we're done
				return
			}
			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := tracepointlib.ConvertToEvent[ptraceEvent](&record)
		event := t.parseEvent(bpfEvent)
		t.eventCallback(event)
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
		logger.L().Fatal("ptrace Tracer.SetEventHandler - invalid event handler", helpers.Interface("handler", handler))
	}
	t.eventCallback = nh
}

func (t *Tracer) parseEvent(bpfEvent *ptraceEvent) *types.Event {
	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
		Pid:           bpfEvent.Pid,
		PPid:          bpfEvent.Ppid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Request:       bpfEvent.Request,
		Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
		ExePath:       gadgets.FromCString(bpfEvent.Exepath[:]),
	}

	if t.enricher != nil {
		t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
	}

	return &event
}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
