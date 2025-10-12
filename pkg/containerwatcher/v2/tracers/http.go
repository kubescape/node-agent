package tracers

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
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
	httpTraceName    = "trace_http"
	StatusOK         = 200
	StatusBadRequest = 300
)

var _ containerwatcher.TracerInterface = (*HTTPTracer)(nil)

// HTTPTracer implements TracerInterface for HTTP events
type HTTPTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewHTTPTracer creates a new HTTP tracer
func NewHTTPTracer(
	eventCallback containerwatcher.ResultCallback,
	kubeManager *kskubemanager.KubeManager,
	ociStore *orasoci.ReadOnlyStore,
	runtime runtime.Runtime,
) *HTTPTracer {
	return &HTTPTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the HTTP tracer
func (ht *HTTPTracer) Start(ctx context.Context) error {
	ht.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_http:v0.45.0",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ht.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ht.eventOperator(),
		),
	)
	go func() {
		err := ht.runtime.RunGadget(ht.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ht.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the HTTP tracer
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

// GetName returns the unique name of the tracer
func (ht *HTTPTracer) GetEventType() utils.EventType {
	return utils.HTTPEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ht *HTTPTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DHttp && cfg.EnableHttpDetection
}

// eventOperator returns the event operator for the HTTP tracer
func (ht *HTTPTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.HTTPEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
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

// callback handles HTTP events from the HTTP tracer
func (ht *HTTPTracer) callback(event *utils.DatasourceEvent) {

	// TODO: Implement HTTP tracer and copy all the parsing code of the GroupEvents

	//if event.Type == types.DEBUG {
	//	return
	//}
	//
	//if isDroppedEvent(event.Type, event.Message) {
	//	logger.L().Warning("http tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
	//	return
	//}

	if event.Response != nil {
		if event.Response.StatusCode < StatusOK || event.Response.StatusCode >= StatusBadRequest {
			return
		}
	}

	if ht.eventCallback != nil {
		// Extract container ID and process ID from the HTTP event
		//containerID := event.Runtime.ContainerID
		//processID := event.Pid
		//
		//ht.eventCallback(event, containerID, processID)
	}
}
