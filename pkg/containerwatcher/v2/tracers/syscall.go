package tracers

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
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

const syscallTraceName = "syscall_tracer"

var _ containerwatcher.TracerInterface = (*SyscallTracer)(nil)

// SyscallTracer implements TracerInterface for events
type SyscallTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   *kskubemanager.KubeManager
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewSyscallTracer creates a new tracer
func NewSyscallTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *SyscallTracer {
	return &SyscallTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (st *SyscallTracer) Start(ctx context.Context) error {
	st.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/advise_seccomp:v0.45.0",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			st.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			st.eventOperator(),
		),
		gadgetcontext.WithName(syscallTraceName),
		gadgetcontext.WithOrasReadonlyTarget(st.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.oci.ebpf.map-fetch-count":    "0",
			"operator.oci.ebpf.map-fetch-interval": "5s",
		}
		err := st.runtime.RunGadget(st.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", st.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (st *SyscallTracer) Stop() error {
	if st.gadgetCtx != nil {
		st.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (st *SyscallTracer) GetName() string {
	return syscallTraceName
}

// GetEventType returns the event type this tracer produces
func (st *SyscallTracer) GetEventType() utils.EventType {
	return utils.SyscallEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (st *SyscallTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DSeccomp {
		return false
	}
	return cfg.EnableRuntimeDetection || cfg.EnableSeccomp
}

func (st *SyscallTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.SyscallEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					logger.L().Debug("Matthias - syscall event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					st.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.SyscallEventType})
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
func (st *SyscallTracer) callback(event utils.EverythingEvent) {
	containerID := event.GetContainerID()
	if containerID == "" {
		return
	}

	st.eventCallback(event, containerID, 0)
}
