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
	ptraceImageName = "ghcr.io/inspektor-gadget/gadget/ptrace:latest"
	ptraceTraceName = "trace_ptrace"
)

var _ containerwatcher.TracerInterface = (*PtraceTracer)(nil)

// PtraceTracer implements TracerInterface for events
type PtraceTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewPtraceTracer creates a new tracer
func NewPtraceTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *PtraceTracer {
	return &PtraceTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (pt *PtraceTracer) Start(ctx context.Context) error {
	pt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		ptraceImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			pt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			pt.eventOperator(),
		),
		gadgetcontext.WithName(ptraceTraceName),
		gadgetcontext.WithOrasReadonlyTarget(pt.ociStore),
	)
	go func() {
		err := pt.runtime.RunGadget(pt.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", pt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (pt *PtraceTracer) Stop() error {
	if pt.gadgetCtx != nil {
		pt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (pt *PtraceTracer) GetName() string {
	return ptraceTraceName
}

// GetEventType returns the event type this tracer produces
func (pt *PtraceTracer) GetEventType() utils.EventType {
	return utils.PtraceEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (pt *PtraceTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DPtrace && cfg.EnableRuntimeDetection
}

func (pt *PtraceTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.PtraceEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					pt.callback(&utils.DatasourceEvent{Datasource: d, Data: data.DeepCopy(), EventType: utils.PtraceEventType})
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
func (pt *PtraceTracer) callback(event utils.PtraceEvent) {
	if pt.eventCallback != nil {
		// Extract container ID and process ID from the ptrace event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		pt.eventCallback(event, containerID, processID)
	}
}
