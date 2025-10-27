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

const symlinkTraceName = "trace_symlink"

var _ containerwatcher.TracerInterface = (*SymlinkTracer)(nil)

// SymlinkTracer implements TracerInterface for events
type SymlinkTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewSymlinkTracer creates a new tracer
func NewSymlinkTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *SymlinkTracer {
	return &SymlinkTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (st *SymlinkTracer) Start(ctx context.Context) error {
	st.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/symlink:latest",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			st.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			st.eventOperator(),
		),
		gadgetcontext.WithName(symlinkTraceName),
		gadgetcontext.WithOrasReadonlyTarget(st.ociStore),
	)
	go func() {
		err := st.runtime.RunGadget(st.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", st.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the symlink tracer
func (st *SymlinkTracer) Stop() error {
	if st.gadgetCtx != nil {
		st.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (st *SymlinkTracer) GetName() string {
	return symlinkTraceName
}

// GetEventType returns the event type this tracer produces
func (st *SymlinkTracer) GetEventType() utils.EventType {
	return utils.SymlinkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (st *SymlinkTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DSymlink && cfg.EnableRuntimeDetection
}

func (st *SymlinkTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.SymlinkEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					st.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.SymlinkEventType})
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
func (st *SymlinkTracer) callback(event utils.LinkEvent) {
	// Handle the event with syscall enrichment
	st.handleEvent(event, []uint64{SYS_SYMLINK, SYS_SYMLINKAT})
}

// handleEvent processes the event with syscall enrichment
func (st *SymlinkTracer) handleEvent(event utils.LinkEvent, syscalls []uint64) {
	if st.eventCallback != nil {
		// Extract container ID and process ID from the symlink event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		enrichEvent(st.thirdPartyEnricher, event, syscalls, st.eventCallback, containerID, processID)
	}
}
