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
	forkImageName = "ghcr.io/inspektor-gadget/gadget/fork:latest"
	forkTraceName = "trace_fork"
)

var _ containerwatcher.TracerInterface = (*ForkTracer)(nil)

// ForkTracer implements TracerInterface for events
type ForkTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewForkTracer creates a new tracer
func NewForkTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *ForkTracer {
	return &ForkTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (ft *ForkTracer) Start(ctx context.Context) error {
	ft.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		forkImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ft.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ft.eventOperator(),
		),
		gadgetcontext.WithName(forkTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ft.ociStore),
	)
	go func() {
		err := ft.runtime.RunGadget(ft.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ft.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the fork tracer
func (ft *ForkTracer) Stop() error {
	if ft.gadgetCtx != nil {
		ft.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ft *ForkTracer) GetName() string {
	return forkTraceName
}

// GetEventType returns the event type this tracer produces
func (ft *ForkTracer) GetEventType() utils.EventType {
	return utils.ForkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ft *ForkTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DFork {
		return false
	}
	return cfg.EnableApplicationProfile || cfg.EnableRuntimeDetection
}

func (ft *ForkTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.ForkEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					ft.callback(&utils.DatasourceEvent{Datasource: d, Data: data.DeepCopy(), EventType: utils.ForkEventType})
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
func (ft *ForkTracer) callback(event utils.ForkEvent) {
	if ft.eventCallback != nil {
		// Extract container ID and process ID from the fork event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		ft.eventCallback(event, containerID, processID)
	}
}
