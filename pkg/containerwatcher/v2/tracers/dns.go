package tracers

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
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
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	dnsImageName = "ghcr.io/inspektor-gadget/gadget/trace_dns:v0.48.1"
	dnsTraceName = "trace_dns"
)

var _ containerwatcher.TracerInterface = (*DNSTracer)(nil)

// DNSTracer implements TracerInterface for events
type DNSTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeManager        operators.DataOperator
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	socketEnricherOp   *socketenricher.SocketEnricher
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewDNSTracer creates a new tracer
func NewDNSTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	socketEnricherOp *socketenricher.SocketEnricher,
) *DNSTracer {
	return &DNSTracer{
		eventCallback:      eventCallback,
		kubeManager:        kubeManager,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
		socketEnricherOp:   socketEnricherOp,
	}
}

// Start initializes and starts the tracer
func (dt *DNSTracer) Start(ctx context.Context) error {
	dt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		dnsImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			dt.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			dt.socketEnricherOp,
			NewDnsOperator(),
			dt.eventOperator(),
		),
		gadgetcontext.WithName(dnsTraceName),
		gadgetcontext.WithOrasReadonlyTarget(dt.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.oci.ebpf.paths": "true", // CWD paths in events
		}
		err := dt.runtime.RunGadget(dt.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", dt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (dt *DNSTracer) Stop() error {
	if dt.socketEnricherOp != nil {
		dt.socketEnricherOp.Close()
	}
	if dt.gadgetCtx != nil {
		dt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (dt *DNSTracer) GetName() string {
	return dnsTraceName
}

// GetEventType returns the event type this tracer produces
func (dt *DNSTracer) GetEventType() utils.EventType {
	return utils.DnsEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (dt *DNSTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DDns {
		return false
	}
	return cfg.EnableNetworkTracing || cfg.EnableRuntimeDetection
}

func (dt *DNSTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.DnsEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					dt.callback(&utils.DatasourceEvent{Datasource: d, Data: source.DeepCopy(data), EventType: utils.DnsEventType})
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
func (dt *DNSTracer) callback(event utils.DNSEvent) {
	if event.GetQr() != utils.DNSPktTypeResponse {
		return
	}

	if event.GetNumAnswers() == 0 {
		return
	}

	if dt.eventCallback != nil {
		// Extract container ID and process ID from the DNS event
		containerID := event.GetContainerID()
		processID := event.GetPID()

		dt.eventCallback(event, containerID, processID)
	}
}
