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

const capabilitiesTraceName = "trace_capabilities"

var _ containerwatcher.TracerInterface = (*CapabilitiesTracer)(nil)

// CapabilitiesTracer implements TracerInterface for events
type CapabilitiesTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewCapabilitiesTracer creates a new tracer
func NewCapabilitiesTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *CapabilitiesTracer {
	return &CapabilitiesTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (ct *CapabilitiesTracer) Start(ctx context.Context) error {
	ct.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_capabilities:v0.45.0",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ct.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ct.eventOperator(),
		),
		gadgetcontext.WithName(capabilitiesTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ct.ociStore),
	)
	go func() {
		err := ct.runtime.RunGadget(ct.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ct.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (ct *CapabilitiesTracer) Stop() error {
	if ct.gadgetCtx != nil {
		ct.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ct *CapabilitiesTracer) GetName() string {
	return capabilitiesTraceName
}

// GetEventType returns the event type this tracer produces
func (ct *CapabilitiesTracer) GetEventType() utils.EventType {
	return utils.CapabilitiesEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ct *CapabilitiesTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DCapSys && cfg.EnableRuntimeDetection
}

func (ct *CapabilitiesTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.CapabilitiesEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					ct.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.CapabilitiesEventType})
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
func (ct *CapabilitiesTracer) callback(event utils.CapabilitiesEvent) {
	if ct.eventCallback != nil {
		// Extract container ID and process ID from the capabilities event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		ct.eventCallback(event, containerID, processID)
	}
}
