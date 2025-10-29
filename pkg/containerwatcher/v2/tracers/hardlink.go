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
	hardlinkImageName = "ghcr.io/inspektor-gadget/gadget/hardlink:latest"
	hardlinkTraceName = "trace_hardlink"
)

var _ containerwatcher.TracerInterface = (*HardlinkTracer)(nil)

// HardlinkTracer implements TracerInterface for events
type HardlinkTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewHardlinkTracer creates a new tracer
func NewHardlinkTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *HardlinkTracer {
	return &HardlinkTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (ht *HardlinkTracer) Start(ctx context.Context) error {
	ht.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		hardlinkImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ht.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ht.eventOperator(),
		),
		gadgetcontext.WithName(hardlinkTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ht.ociStore),
	)
	go func() {
		err := ht.runtime.RunGadget(ht.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ht.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (ht *HardlinkTracer) Stop() error {
	if ht.gadgetCtx != nil {
		ht.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ht *HardlinkTracer) GetName() string {
	return hardlinkTraceName
}

// GetEventType returns the event type this tracer produces
func (ht *HardlinkTracer) GetEventType() utils.EventType {
	return utils.HardlinkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ht *HardlinkTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DHardlink && cfg.EnableRuntimeDetection
}

func (ht *HardlinkTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.HardlinkEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					ht.callback(&utils.DatasourceEvent{Datasource: d, Data: data.DeepCopy(), EventType: utils.HardlinkEventType})
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
func (ht *HardlinkTracer) callback(event utils.LinkEvent) {
	// Handle the event with syscall enrichment
	ht.handleEvent(event, []uint64{SYS_LINK, SYS_LINKAT})
}

// handleEvent processes the event with syscall enrichment
func (ht *HardlinkTracer) handleEvent(event utils.LinkEvent, syscalls []uint64) {
	if ht.eventCallback != nil {
		// Extract container ID and process ID from the hardlink event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		enrichEvent(ht.thirdPartyEnricher, event, syscalls, ht.eventCallback, containerID, processID)
	}
}
