package tracer

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/utils"
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
	eventsMap       *utils.CacheWithKeys // Map of unique identifiers to events, thread-safe
	timeoutDuration time.Duration
	timeoutTicker   *time.Ticker
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:          config,
		enricher:        enricher,
		eventCallback:   eventCallback,
		eventsMap:       utils.NewCacheWithKeys(types.MaxGroupedEventSize),
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
		l, err := AttachTracepoint(tp)
		if err != nil {
			logger.L().Error(fmt.Sprintf("Error attaching tracepoint: %s", err))
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
				// nothing to do, we're done
				continue
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

	if eventType == types.Request {

		event, err := CreateEventFromRequest(bpfEvent)
		if err != nil {
			msg := fmt.Sprintf("Error parsing request: %s", err)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			return nil
		}
		fmt.Println("Time", ToTime(event.Timestamp))
		t.eventsMap.Add(GetUniqueIdentifier(bpfEvent), event)

	} else if eventType == types.Response {

		if exists, ok := t.eventsMap.Get(GetUniqueIdentifier(bpfEvent)); ok {
			grouped := exists.(*types.Event)

			response, err := ParseHTTPResponse(FromCString(bpfEvent.Buf[:]), grouped.Request)
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
	fmt.Println("Starting cleanupOldRequests")
	for range t.timeoutTicker.C {
		for _, key := range t.eventsMap.Keys() {
			if exists, ok := t.eventsMap.Get(key); ok {
				if event, ok := exists.(*types.Event); ok {
					if time.Since(ToTime(event.Timestamp)) > t.timeoutDuration {
						t.eventsMap.Remove(key)
						logger.L().Debug(fmt.Sprintf("Removed expired request: %s", key))
					}
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
