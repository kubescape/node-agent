package tracers

import (
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/kskubemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	httpTraceName       = "trace_http"
	MaxGroupedEventSize = 10000
	StatusOK            = 200
	StatusBadRequest    = 300
)

var _ containerwatcher.TracerInterface = (*HTTPTracer)(nil)

// HTTPTracer implements TracerInterface for events
type HTTPTracer struct {
	eventCallback   containerwatcher.ResultCallback
	eventsMap       *lru.Cache[string, utils.HttpEvent] // Use golang-lru cache
	gadgetCtx       *gadgetcontext.GadgetContext
	kubeManager     *kskubemanager.KubeManager
	ociStore        *orasoci.ReadOnlyStore
	runtime         runtime.Runtime
	timeoutDuration time.Duration
	timeoutTicker   *time.Ticker
}

// NewHTTPTracer creates a new tracer
func NewHTTPTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *HTTPTracer {
	// Create a new LRU cache with a specified size
	cache, err := lru.New[string, utils.HttpEvent](MaxGroupedEventSize)
	if err != nil {
		return nil
	}
	t := &HTTPTracer{
		eventCallback:   eventCallback,
		eventsMap:       cache,
		kubeManager:     kubeManager,
		ociStore:        ociStore,
		runtime:         runtime,
		timeoutDuration: 5 * time.Second,
	}
	t.timeoutTicker = time.NewTicker(t.timeoutDuration)
	go t.transmitOrphanRequests()
	return t
}

// Start initializes and starts the tracer
func (ht *HTTPTracer) Start(ctx context.Context) error {
	ht.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/http:latest",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ht.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ht.eventOperator(),
		),
		gadgetcontext.WithName(httpTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ht.ociStore),
	)
	go func() {
		err := ht.runtime.RunGadget(ht.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ht.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (ht *HTTPTracer) Stop() error {
	if ht.gadgetCtx != nil {
		ht.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ht *HTTPTracer) GetName() string {
	return httpTraceName
}

// GetEventType returns the event type this tracer produces
func (ht *HTTPTracer) GetEventType() utils.EventType {
	return utils.HTTPEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ht *HTTPTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DHttp && cfg.EnableHttpDetection
}

func (ht *HTTPTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.HTTPEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					logger.L().Debug("Matthias - http event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					ht.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.HTTPEventType})
					return nil
				}, opPriority)
				if err != nil {
					return err
				}
			}
			return nil
		}), simple.WithPriority(opPriority),
	)
}

// callback handles events from the tracer
func (ht *HTTPTracer) callback(event utils.HttpRawEvent) {
	if grouped := ht.GroupEvents(event); grouped != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()
		ht.eventCallback(grouped, containerID, processID)
	}
}

func (ht *HTTPTracer) transmitOrphanRequests() {
	for range ht.timeoutTicker.C {
		keys := ht.eventsMap.Keys()
		for _, key := range keys {
			if event, ok := ht.eventsMap.Peek(key); ok {
				if time.Since(ToTime(event.GetTimestamp())) > ht.timeoutDuration {
					containerID := event.GetContainerID()
					processID := event.GetPID()
					ht.eventCallback(event, containerID, processID)
					ht.eventsMap.Remove(key)
				}
			}
		}
	}
}

func (ht *HTTPTracer) GroupEvents(bpfEvent utils.HttpRawEvent) utils.HttpEvent {
	id := GetUniqueIdentifier(bpfEvent)
	switch bpfEvent.GetType() {
	case utils.Request:
		event, err := CreateEventFromRequest(bpfEvent)
		if err != nil {
			return nil
		}
		ht.eventsMap.Add(id, event)
	case utils.Response:
		if exists, ok := ht.eventsMap.Get(id); ok {
			grouped := exists
			request, response, err := ParseHttpResponse(FromCString(bpfEvent.GetBuf()))
			if err != nil {
				return nil
			}

			grouped.SetRequest(request)
			grouped.SetResponse(response)
			ht.eventsMap.Remove(id)
			return grouped
		}
	}
	return nil
}
