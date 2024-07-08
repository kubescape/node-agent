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
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type event antitampering bpf/antitampering.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap          *ebpf.Map
	AllowedPids         *ebpf.Map
	RestrictedMapsNames *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs antitamperingObjects

	bpfMapLsmLink link.Link
	reader        *perf.Reader
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
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	t.bpfMapLsmLink = gadgets.CloseLink(t.bpfMapLsmLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	spec, err := loadAntitampering()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.bpfMapLsmLink, err = link.AttachLSM(link.LSMOptions{Program: t.objs.antitamperingPrograms.TraceTampering})
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.antitamperingMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*antitamperingEvent)(unsafe.Pointer(&record.RawSample[0]))

		// Check if we have seen enough events for this mntns
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
			UpperLayer:    bpfEvent.UpperLayer,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			ExePath:       gadgets.FromCString(bpfEvent.Exepath[:]),
			MapName:       gadgets.FromCString(bpfEvent.MapName[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		logger.L().Info("antitampering event", helpers.Interface("event", event))

		t.eventCallback(&event)
	}
}

// --- Registry changes

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

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}