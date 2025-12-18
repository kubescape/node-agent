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
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	bpfImageName = "ghcr.io/inspektor-gadget/gadget/bpf:latest"
	bpfTraceName = "trace_bpf"
)

var _ containerwatcher.TracerInterface = (*BpfTracer)(nil)

// BpfTracer implements TracerInterface for events
type BpfTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        operators.DataOperator
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewBpfTracer creates a new tracer
func NewBpfTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *BpfTracer {
	return &BpfTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (bt *BpfTracer) Start(ctx context.Context) error {
	bt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		bpfImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			bt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			bt.eventOperator(),
		),
		gadgetcontext.WithName(bpfTraceName),
		gadgetcontext.WithOrasReadonlyTarget(bt.ociStore),
	)
	go func() {
		err := bt.runtime.RunGadget(bt.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", bt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the bpf tracer
func (bt *BpfTracer) Stop() error {
	if bt.gadgetCtx != nil {
		bt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (bt *BpfTracer) GetName() string {
	return bpfTraceName
}

// GetEventType returns the event type this tracer produces
func (bt *BpfTracer) GetEventType() utils.EventType {
	return utils.BpfEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (bt *BpfTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DBpf && cfg.EnableRuntimeDetection
}

func (bt *BpfTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.BpfEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					pooledData := utils.GetPooledDataItem(utils.BpfEventType).(*datasource.Edata)
					data.DeepCopyInto(pooledData)
					bt.callback(&utils.DatasourceEvent{Datasource: d, Data: pooledData, EventType: utils.BpfEventType})
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
func (bt *BpfTracer) callback(event utils.BpfEvent) {
	if bt.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()

		bt.eventCallback(event, containerID, processID)
	}
}
