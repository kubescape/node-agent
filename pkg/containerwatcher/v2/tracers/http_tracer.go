package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	tracerhttp "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	httpTraceName    = "trace_http"
	StatusOK         = 200
	StatusBadRequest = 300
)

// HTTPTracer implements TracerInterface for HTTP events
type HTTPTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent)
	tracer              *tracerhttp.Tracer
}

// NewHTTPTracer creates a new HTTP tracer
func NewHTTPTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent),
) *HTTPTracer {
	return &HTTPTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the HTTP tracer
func (ht *HTTPTracer) Start(ctx context.Context) error {
	if err := ht.tracerCollection.AddTracer(httpTraceName, ht.containerSelector); err != nil {
		return fmt.Errorf("adding HTTP tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	httpMountnsmap, err := ht.tracerCollection.TracerMountNsMap(httpTraceName)
	if err != nil {
		return fmt.Errorf("getting HTTP mountnsmap: %w", err)
	}

	tracerHttp, err := tracerhttp.NewTracer(
		&tracerhttp.Config{MountnsMap: httpMountnsmap},
		ht.containerCollection,
		ht.httpEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating HTTP tracer: %w", err)
	}

	ht.tracer = tracerHttp
	return nil
}

// Stop gracefully stops the HTTP tracer
func (ht *HTTPTracer) Stop() error {
	if ht.tracer != nil {
		ht.tracer.Close()
	}

	if err := ht.tracerCollection.RemoveTracer(httpTraceName); err != nil {
		return fmt.Errorf("removing HTTP tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (ht *HTTPTracer) GetName() string {
	return "http_tracer"
}

// GetEventType returns the event type this tracer produces
func (ht *HTTPTracer) GetEventType() utils.EventType {
	return utils.HTTPEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ht *HTTPTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableHttpDetection
	}
	return false
}

// httpEventCallback handles HTTP events from the tracer
func (ht *HTTPTracer) httpEventCallback(event *tracerhttptype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("http tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	if event.Response != nil {
		if event.Response.StatusCode < StatusOK || event.Response.StatusCode >= StatusBadRequest {
			return
		}
	}

	if ht.eventCallback != nil {
		ht.eventCallback(event)
	}
}
