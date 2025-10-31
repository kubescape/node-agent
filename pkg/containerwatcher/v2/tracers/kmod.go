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
	kmodImageName = "ghcr.io/inspektor-gadget/gadget/kmod:latest"
	kmodTraceName = "trace_kmod"
)

var _ containerwatcher.TracerInterface = (*KmodTracer)(nil)

// KmodTracer implements TracerInterface for events
type KmodTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewKmodTracer creates a new tracer
func NewKmodTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *KmodTracer {
	return &KmodTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (kt *KmodTracer) Start(ctx context.Context) error {
	kt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		kmodImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			kt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			kt.eventOperator(),
		),
		gadgetcontext.WithName(kmodTraceName),
		gadgetcontext.WithOrasReadonlyTarget(kt.ociStore),
	)
	go func() {
		err := kt.runtime.RunGadget(kt.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", kt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the kmod tracer
func (kt *KmodTracer) Stop() error {
	if kt.gadgetCtx != nil {
		kt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (kt *KmodTracer) GetName() string {
	return kmodTraceName
}

// GetEventType returns the event type this tracer produces
func (kt *KmodTracer) GetEventType() utils.EventType {
	return utils.KmodEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (kt *KmodTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DKmod && cfg.EnableRuntimeDetection
}

func (kt *KmodTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.KmodEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					kt.callback(&utils.DatasourceEvent{Datasource: d, Data: data.DeepCopy(), EventType: utils.KmodEventType})
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
func (kt *KmodTracer) callback(event utils.KmodEvent) {
	if kt.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()

		kt.eventCallback(event, containerID, processID)
	}
}
