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

const execTraceName = "trace_exec"

var _ containerwatcher.TracerInterface = (*ExecTracer)(nil)

// ExecTracer implements TracerInterface for events
type ExecTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        *kskubemanager.KubeManager
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewExecTracer creates a new tracer
func NewExecTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *ExecTracer {
	return &ExecTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (et *ExecTracer) Start(ctx context.Context) error {
	et.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_exec:v0.45.0",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			et.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			et.eventOperator(),
		),
		gadgetcontext.WithName(execTraceName),
		gadgetcontext.WithOrasReadonlyTarget(et.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.oci.ebpf.paths": "true", // CWD paths in events
		}
		err := et.runtime.RunGadget(et.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", et.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (et *ExecTracer) Stop() error {
	if et.gadgetCtx != nil {
		et.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (et *ExecTracer) GetName() string {
	return execTraceName
}

// GetEventType returns the event type this tracer produces
func (et *ExecTracer) GetEventType() utils.EventType {
	return utils.ExecveEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (et *ExecTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DExec {
		return false
	}
	return cfg.EnableApplicationProfile || cfg.EnableRuntimeDetection
}

func (et *ExecTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.ExecveEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					et.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.ExecveEventType})
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
func (et *ExecTracer) callback(event utils.ExecEvent) {
	errorRaw := event.GetError()
	if errorRaw > -1 && event.GetComm() != "" {
		// Handle the event with syscall enrichment
		et.handleEvent(event, []uint64{SYS_FORK})
	}
}

// handleEvent processes the event with syscall enrichment
func (et *ExecTracer) handleEvent(event utils.ExecEvent, syscalls []uint64) {
	if et.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()

		enrichEvent(et.thirdPartyEnricher, event, syscalls, et.eventCallback, containerID, processID)
	}
}
