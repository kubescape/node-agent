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
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	unshareImageName = "ghcr.io/inspektor-gadget/gadget/unshare:latest"
	unshareTraceName = "trace_unshare"
)

var _ containerwatcher.TracerInterface = (*UnshareTracer)(nil)

// UnshareTracer implements TracerInterface for events
type UnshareTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewUnshareTracer creates a new tracer
func NewUnshareTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *UnshareTracer {
	return &UnshareTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (ut *UnshareTracer) Start(ctx context.Context) error {
	ut.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		unshareImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ut.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ut.eventOperator(),
		),
		gadgetcontext.WithName(unshareTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ut.ociStore),
	)
	go func() {
		err := ut.runtime.RunGadget(ut.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ut.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the unshare tracer
func (ut *UnshareTracer) Stop() error {
	if ut.gadgetCtx != nil {
		ut.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ut *UnshareTracer) GetName() string {
	return unshareTraceName
}

// GetEventType returns the event type this tracer produces
func (ut *UnshareTracer) GetEventType() utils.EventType {
	return utils.UnshareEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ut *UnshareTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DUnshare && cfg.EnableRuntimeDetection
}

func (ut *UnshareTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.UnshareEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					ut.callback(&utils.DatasourceEvent{Datasource: d, Data: data.DeepCopy(), EventType: utils.UnshareEventType})
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
func (ut *UnshareTracer) callback(event utils.UnshareEvent) {
	if ut.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()

		ut.eventCallback(event, containerID, processID)
	}
}
