package tracers

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/kskubemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const sshTraceName = "trace_ssh"

var _ containerwatcher.TracerInterface = (*SSHTracer)(nil)

// SSHTracer implements TracerInterface for events
type SSHTracer struct {
	eventCallback    containerwatcher.ResultCallback
	gadgetCtx        *gadgetcontext.GadgetContext
	kubeManager      *kskubemanager.KubeManager
	ociStore         *orasoci.ReadOnlyStore
	runtime          runtime.Runtime
	socketEnricherOp *socketenricher.SocketEnricher
}

// NewSSHTracer creates a new tracer
func NewSSHTracer(
	kubeManager *kskubemanager.KubeManager,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	socketEnricherOp *socketenricher.SocketEnricher,
) *SSHTracer {
	return &SSHTracer{
		eventCallback:    eventCallback,
		kubeManager:      kubeManager,
		ociStore:         ociStore,
		runtime:          runtime,
		socketEnricherOp: socketEnricherOp,
	}
}

// Start initializes and starts the tracer
func (st *SSHTracer) Start(ctx context.Context) error {
	st.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/ssh:latest",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			st.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			st.socketEnricherOp,
			st.eventOperator(),
		),
		gadgetcontext.WithName(sshTraceName),
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

// Stop gracefully stops the tracer
func (st *SSHTracer) Stop() error {
	if st.socketEnricherOp != nil {
		st.socketEnricherOp.Close()
	}
	if st.gadgetCtx != nil {
		st.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (st *SSHTracer) GetName() string {
	return sshTraceName
}

// GetEventType returns the event type this tracer produces
func (st *SSHTracer) GetEventType() utils.EventType {
	return utils.SSHEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (st *SSHTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DSsh && cfg.EnableRuntimeDetection
}

func (st *SSHTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.SSHEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					logger.L().Debug("Matthias - ssh event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					st.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.SSHEventType})
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
func (st *SSHTracer) callback(event utils.SshEvent) {
	if st.eventCallback != nil {
		// Extract container ID and process ID from the SSH event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		st.eventCallback(event, containerID, processID)
	}
}
