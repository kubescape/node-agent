package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"k8s.io/utils/lru"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -strip /usr/bin/llvm-strip-18  -cc /usr/bin/clang -no-global-types -target bpfel -cc clang -cflags "-g -O2 -Wall" -type active_connection_info -type packet_buffer -type httpevent http_sniffer bpf/http-sniffer.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.GroupedHTTP)

	objs http_snifferObjects

	httplinks []link.Link
	reader    *perf.Reader
	eventsMap *lru.Cache
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.GroupedHTTP),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
		eventsMap:     lru.New(types.MaxGroupedEventSize),
	}

	if err := t.install(); err != nil {
		t.Close()
		return nil, err
	}

	go t.run()

	return t, nil
}

func (t *Tracer) Close() {
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
		event, err := t.ParseHTTP(bpfEvent)
		if err != nil {
			msg := fmt.Sprintf("Error parsing sample: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			continue
		}

		if grouped := t.GroupEvents(event, event.HttpData); grouped != nil {

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

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.GroupedHTTP))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *Tracer) GroupEvents(event *types.Event, httpData types.HTTPData) *types.GroupedHTTP {

	if event.DataType == types.Request {
		grouped := types.GroupedHTTP{
			Request:  httpData.(*types.HTTPRequest),
			Response: nil,
		}
		grouped.MountNsID = event.MountNsID
		grouped.Event = event.Event
		t.eventsMap.Add(event.GetUniqueIdentifier(), &grouped) // check

	} else if event.DataType == types.Response {
		if exists, ok := t.eventsMap.Get(event.GetUniqueIdentifier()); ok {
			grouped := exists.(*types.GroupedHTTP)
			grouped.Response = httpData.(*types.HTTPResponse)
			t.eventsMap.Remove(event.GetUniqueIdentifier())
			return grouped
		}

	}
	return nil

}

type GadgetDesc struct{}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
