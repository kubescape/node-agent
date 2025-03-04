package tracer

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	lru "github.com/hashicorp/golang-lru/v2"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracepointlib "github.com/kubescape/node-agent/pkg/ebpf/lib"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -strip /usr/bin/llvm-strip-18  -cc /usr/bin/clang -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type active_connection_info -type packet_buffer -type httpevent http_sniffer bpf/http-sniffer.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs http_snifferObjects

	httplinks       []link.Link
	reader          *perf.Reader
	eventsMap       *lru.Cache[string, *types.Event] // Use golang-lru cache
	timeoutDuration time.Duration
	timeoutTicker   *time.Ticker
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	// Create a new LRU cache with a specified size
	cache, err := lru.New[string, *types.Event](types.MaxGroupedEventSize)
	if err != nil {
		return nil, fmt.Errorf("creating lru cache: %w", err)
	}

	t := &Tracer{
		config:          config,
		enricher:        enricher,
		eventCallback:   eventCallback,
		eventsMap:       cache,
		timeoutDuration: 1 * time.Minute,
	}

	if err := t.install(); err != nil {
		t.Close()
		return nil, err
	}

	t.timeoutTicker = time.NewTicker(30 * time.Second)
	go t.cleanupOldRequests()

	go t.run()

	return t, nil
}

func (t *Tracer) Close() {
	// Stop the timeout ticker
	if t.timeoutTicker != nil {
		t.timeoutTicker.Stop()
	}

	for _, l := range t.httplinks {
		gadgets.CloseLink(l)
	}

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	spec, err := loadHttp_sniffer()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	tracepoints := GetTracepointDefinitions(&t.objs.http_snifferPrograms)
	var links []link.Link
	for _, tp := range tracepoints {
		l, err := tracepointlib.AttachTracepoint(tp)
		if err != nil {
			logger.L().Fatal("http Tracer - error attaching tracepoint", helpers.Error(err))
		}
		links = append(links, l)
	}

	t.httplinks = links

	t.reader, err = perf.NewReader(t.objs.http_snifferMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*http_snifferHttpevent)(unsafe.Pointer(&record.RawSample[0]))

		if grouped := t.GroupEvents(bpfEvent); grouped != nil {
			// We'll only enrich by request properties
			if t.enricher != nil {
				t.enricher.EnrichByMntNs(&grouped.CommonData, grouped.MountNsID)
			}
			t.eventCallback(grouped)
		}
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.Close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)
	go t.cleanupOldRequests()

	return nil
}

func (t *Tracer) GroupEvents(bpfEvent *http_snifferHttpevent) *types.Event {
	eventType := types.HTTPDataType(bpfEvent.Type)
	syscall := gadgets.FromCString(bpfEvent.Syscall[:])
	direction, err := types.GetPacketDirection(syscall)
	if err != nil {
		logger.L().Debug("http Tracer.GroupEvents - error getting packet direction", helpers.Error(err),
			helpers.String("syscall", syscall))
		return nil
	}

	if eventType == types.Request && direction == consts.Inbound {
		event, err := CreateEventFromRequest(bpfEvent)
		if err != nil {
			msg := fmt.Sprintf("Error parsing request: %s", err)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			return nil
		}
		t.eventsMap.Add(GetUniqueIdentifier(bpfEvent), event)
	} else if eventType == types.Response {
		if exists, ok := t.eventsMap.Get(GetUniqueIdentifier(bpfEvent)); ok {
			grouped := exists
			response, err := ParseHttpResponse(FromCString(bpfEvent.Buf[:]), grouped.Request)
			if err != nil {
				msg := fmt.Sprintf("Error parsing response: %s", err)
				t.eventCallback(types.Base(eventtypes.Warn(msg)))
				return nil
			}

			grouped.Response = response
			t.eventsMap.Remove(GetUniqueIdentifier(bpfEvent))
			return grouped
		}
	}

	return nil
}

func (t *Tracer) cleanupOldRequests() {
	for range t.timeoutTicker.C {
		keys := t.eventsMap.Keys()
		for _, key := range keys {
			if event, ok := t.eventsMap.Peek(key); ok {
				if time.Since(ToTime(event.Timestamp)) > t.timeoutDuration {
					t.eventsMap.Remove(key)
				}
			}
		}
	}
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		logger.L().Fatal("http Tracer.SetEventHandler - invalid event handler", helpers.Interface("handler", handler))
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
