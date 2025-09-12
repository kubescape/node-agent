package tracers

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const openTraceName = "trace_open"

var _ containerwatcher.TracerInterface = (*OpenTracer)(nil)

// OpenTracer implements TracerInterface for open events
type OpenTracer struct {
	cfg                config.Config
	containerSelector  containercollection.ContainerSelector
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	ociStore           *orasoci.ReadOnlyStore
	orderedEventQueue  EventQueueInterface
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewOpenTracer creates a new open tracer
func NewOpenTracer(
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *OpenTracer {
	return &OpenTracer{
		containerSelector:  containerSelector,
		eventCallback:      eventCallback,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the open tracer
func (ot *OpenTracer) Start(ctx context.Context) error {
	ot.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_open:v0.44.1",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			kubemanager.KubeManagerOperator,
			//KubeNameResolver,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ot.eventOperator(),
		),
		gadgetcontext.WithName(openTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ot.ociStore),
	)
	go func() {
		err := ot.runtime.RunGadget(ot.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ot.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the open tracer
func (ot *OpenTracer) Stop() error {
	if ot.gadgetCtx != nil {
		ot.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ot *OpenTracer) GetName() string {
	return openTraceName
}

// GetEventType returns the event type this tracer produces
func (ot *OpenTracer) GetEventType() utils.EventType {
	return utils.OpenEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ot *OpenTracer) IsEnabled(cfg config.Config) bool {
	ot.cfg = cfg
	if cfg.DOpen {
		return false
	}
	return cfg.EnableApplicationProfile || cfg.EnableRuntimeDetection
}

func (ot *OpenTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.OpenEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					ot.callback(&utils.EnrichEvent{Datasource: d, Data: data, EventType: utils.OpenEventType})
					return nil
				}, opPriority)
				if err != nil {
					return err
				}
			}
			return nil
		}),
	)
}

// callback handles open events from the tracer
func (ot *OpenTracer) callback(event *utils.EnrichEvent) {
	if event.GetContainer() == "" {
		return
	}

	errorRaw := event.GetError()
	if errorRaw > -1 {
		// Handle the event with syscall enrichment
		ot.handleEvent(event, []uint64{SYS_OPEN, SYS_OPENAT})
	}
}

// handleEvent processes the event with syscall enrichment
func (ot *OpenTracer) handleEvent(event *utils.EnrichEvent, syscalls []uint64) {
	if ot.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPid()

		EnrichEvent(ot.thirdPartyEnricher, event, syscalls, ot.eventCallback, containerID, processID)
	}
}
