package tracers

import (
	"context"
	goruntime "runtime"

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
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	randomxImageName = "ghcr.io/inspektor-gadget/gadget/randomx:latest"
	randomxTraceName = "trace_randomx"
)

var _ containerwatcher.TracerInterface = (*RandomXTracer)(nil)

// RandomXTracer implements TracerInterface for events
type RandomXTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   operators.DataOperator
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewRandomXTracer creates a new tracer
func NewRandomXTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *RandomXTracer {
	return &RandomXTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (rt *RandomXTracer) Start(ctx context.Context) error {
	rt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		randomxImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			rt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			rt.eventOperator(),
		),
		gadgetcontext.WithName(randomxTraceName),
		gadgetcontext.WithOrasReadonlyTarget(rt.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.LocalManager.host": "true", // don't error if container-collection is nil when using local manager
		}
		err := rt.runtime.RunGadget(rt.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", rt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (rt *RandomXTracer) Stop() error {
	if rt.gadgetCtx != nil {
		rt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (rt *RandomXTracer) GetName() string {
	return randomxTraceName
}

// GetEventType returns the event type this tracer produces
func (rt *RandomXTracer) GetEventType() utils.EventType {
	return utils.RandomXEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (rt *RandomXTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DRandomx && cfg.EnableRuntimeDetection && goruntime.GOARCH == "amd64"
}

func (rt *RandomXTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.RandomXEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					pooledData := utils.GetPooledDataItem(utils.RandomXEventType).(*datasource.Edata)
					data.DeepCopyInto(pooledData)
					rt.callback(&utils.DatasourceEvent{Datasource: d, Data: pooledData, EventType: utils.RandomXEventType})
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
func (rt *RandomXTracer) callback(event utils.EnrichEvent) {
	if rt.eventCallback != nil {
		// Extract container ID and process ID from the randomx event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		rt.eventCallback(event, containerID, processID)
	}
}
