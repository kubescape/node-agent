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
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	auditSeccompImageName = "ghcr.io/inspektor-gadget/gadget/audit_seccomp:v0.48.1"
	auditSeccompTraceName = "audit_seccomp"
)

var _ containerwatcher.TracerInterface = (*AuditSeccompTracer)(nil)

// AuditSeccompTracer reports seccomp decisions the kernel logs, which includes
// the denials of SandboxPolicy profiles (they carry SECCOMP_FILTER_FLAG_LOG).
type AuditSeccompTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        operators.DataOperator
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewAuditSeccompTracer creates a new tracer
func NewAuditSeccompTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *AuditSeccompTracer {
	return &AuditSeccompTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (at *AuditSeccompTracer) Start(ctx context.Context) error {
	at.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		auditSeccompImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			at.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			at.eventOperator(),
		),
		gadgetcontext.WithName(auditSeccompTraceName),
		gadgetcontext.WithOrasReadonlyTarget(at.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.oci.ebpf.collect-kstack": "false",
		}
		err := at.runtime.RunGadget(at.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", at.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (at *AuditSeccompTracer) Stop() error {
	if at.gadgetCtx != nil {
		at.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (at *AuditSeccompTracer) GetName() string {
	return auditSeccompTraceName
}

// GetEventType returns the event type this tracer produces
func (at *AuditSeccompTracer) GetEventType() utils.EventType {
	return utils.AuditSeccompEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (at *AuditSeccompTracer) IsEnabled(cfg config.Config) bool {
	return cfg.EnableSandboxSeccomp
}

func (at *AuditSeccompTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.AuditSeccompEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					at.callback(&utils.DatasourceEvent{Datasource: d, Data: source.DeepCopy(data), EventType: utils.AuditSeccompEventType})
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
func (at *AuditSeccompTracer) callback(event *utils.DatasourceEvent) {
	if at.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()

		at.eventCallback(event, containerID, processID)
	}
}
