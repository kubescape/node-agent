package tracers

import (
	"context"
	"fmt"

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
	kernel "github.com/kubescape/node-agent/pkg/validator/ebpf"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	iouringImageName = "ghcr.io/inspektor-gadget/gadget/iouring_new:latest"
	iouringTraceName = "trace_iouring"
	SupportedMajor   = 6
	SupportedMinor   = 4
)

var _ containerwatcher.TracerInterface = (*IoUringTracer)(nil)

// IoUringTracer implements TracerInterface for events
type IoUringTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewIoUringTracer creates a new tracer
func NewIoUringTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *IoUringTracer {
	return &IoUringTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (it *IoUringTracer) Start(ctx context.Context) error {
	kernelVersion, _ := kernel.GetKernelVersion()
	major, minor, _, err := kernel.ParseKernelVersion(kernelVersion)
	if err != nil {
		return fmt.Errorf("parsing kernel version: %w", err)
	}
	var imageName string
	if major >= SupportedMajor && minor >= SupportedMinor {
		imageName = iouringImageName
	} else {
		imageName = "ghcr.io/inspektor-gadget/gadget/iouring_old:latest"
	}
	it.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		imageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			it.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			it.eventOperator(),
		),
		gadgetcontext.WithName(iouringTraceName),
		gadgetcontext.WithOrasReadonlyTarget(it.ociStore),
	)
	go func() {
		err := it.runtime.RunGadget(it.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", it.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (it *IoUringTracer) Stop() error {
	if it.gadgetCtx != nil {
		it.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (it *IoUringTracer) GetName() string {
	return iouringTraceName
}

// GetEventType returns the event type this tracer produces
func (it *IoUringTracer) GetEventType() utils.EventType {
	return utils.IoUringEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (it *IoUringTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DIouring && cfg.EnableRuntimeDetection
}

func (it *IoUringTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.IoUringEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					pooledData := utils.DataPool.Get().(*datasource.Edata)
					data.DeepCopyInto(pooledData)
					it.callback(&utils.DatasourceEvent{Datasource: d, Data: pooledData, EventType: utils.IoUringEventType})
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
func (it *IoUringTracer) callback(event utils.IOUring) {
	if it.eventCallback != nil {
		// Extract container ID and process ID from the iouring event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		it.eventCallback(event, containerID, processID)
	}
}
