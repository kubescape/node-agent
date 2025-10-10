package tracers

import (
	"context"

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

const exitTraceName = "trace_exit"

var _ containerwatcher.TracerInterface = (*ExitTracer)(nil)

// ExitTracer implements TracerInterface for events
type ExitTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewExitTracer creates a new tracer
func NewExitTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *ExitTracer {
	return &ExitTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (et *ExitTracer) Start(ctx context.Context) error {
	et.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/exit:latest",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			et.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			et.eventOperator(),
		),
		gadgetcontext.WithName(exitTraceName),
		gadgetcontext.WithOrasReadonlyTarget(et.ociStore),
	)
	go func() {
		err := et.runtime.RunGadget(et.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", et.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (et *ExitTracer) Stop() error {
	if et.gadgetCtx != nil {
		et.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (et *ExitTracer) GetName() string {
	return "exit_tracer"
}

// GetEventType returns the event type this tracer produces
func (et *ExitTracer) GetEventType() utils.EventType {
	return utils.ExitEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (et *ExitTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DExit {
		return false
	}
	return cfg.EnableRuntimeDetection || cfg.EnableApplicationProfile
}

func (et *ExitTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.ExitEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					logger.L().Debug("Matthias - exit event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					et.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.ExitEventType})
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
func (et *ExitTracer) callback(event utils.EverythingEvent) {
	if et.eventCallback != nil {
		// Extract container ID and process ID from the exit event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		et.eventCallback(event, containerID, processID)
	}
}
