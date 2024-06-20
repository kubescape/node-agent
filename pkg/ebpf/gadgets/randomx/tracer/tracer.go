//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpf -cc clang -cflags "-g -O2 -Wall" -type event randomx bpf/randomx.bpf.c -- -I./bpf/

const (
	TargetRandomxEventsCount = 50
	MaxSecondsBetweenEvents  = 5
)

type randomxEventCache struct {
	Timestamp   uint64
	EventsCount uint64
	Alerted     bool
}

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs                  randomxObjects
	randomxDeactivateLink link.Link
	reader                *perf.Reader
	mntnsToEventCount     map[uint64]randomxEventCache
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:            config,
		enricher:          enricher,
		eventCallback:     eventCallback,
		mntnsToEventCount: make(map[uint64]randomxEventCache),
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
	t.randomxDeactivateLink = gadgets.CloseLink(t.randomxDeactivateLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	spec, err := loadRandomx()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.randomxDeactivateLink, err = link.Tracepoint("x86_fpu", "x86_fpu_regs_deactivated", t.objs.TracepointX86FpuRegsDeactivated, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.randomxMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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

		bpfEvent := (*randomxEvent)(unsafe.Pointer(&record.RawSample[0]))

		// Check if we have seen this mntns before
		if _, ok := t.mntnsToEventCount[bpfEvent.MntnsId]; !ok {
			t.mntnsToEventCount[bpfEvent.MntnsId] = randomxEventCache{
				Timestamp:   bpfEvent.Timestamp,
				EventsCount: 1,
				Alerted:     false,
			}
		} else if !t.mntnsToEventCount[bpfEvent.MntnsId].Alerted {
			// Check if the last event was too long ago
			if bpfEvent.Timestamp-t.mntnsToEventCount[bpfEvent.MntnsId].Timestamp > MaxSecondsBetweenEvents*1e9 {
				t.mntnsToEventCount[bpfEvent.MntnsId] = randomxEventCache{
					Timestamp:   bpfEvent.Timestamp,
					EventsCount: 1,
					Alerted:     false,
				}
			} else {
				t.mntnsToEventCount[bpfEvent.MntnsId] = randomxEventCache{
					Timestamp:   bpfEvent.Timestamp,
					EventsCount: t.mntnsToEventCount[bpfEvent.MntnsId].EventsCount + 1,
					Alerted:     false,
				}
			}
		} else {
			// We have already alerted for this mntns
			continue
		}

		// Check if we have seen enough events for this mntns
		if t.mntnsToEventCount[bpfEvent.MntnsId].EventsCount > TargetRandomxEventsCount && !t.mntnsToEventCount[bpfEvent.MntnsId].Alerted {
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
			}

			if t.enricher != nil {
				t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
			}

			t.eventCallback(&event)

			t.mntnsToEventCount[bpfEvent.MntnsId] = randomxEventCache{
				Timestamp:   bpfEvent.Timestamp,
				EventsCount: t.mntnsToEventCount[bpfEvent.MntnsId].EventsCount,
				Alerted:     true,
			}

			// Once we have alerted, we don't need to keep track of this mntns anymore.
			t.objs.randomxMaps.GadgetMntnsFilterMap.Put(&bpfEvent.MntnsId, 0)
		}
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
