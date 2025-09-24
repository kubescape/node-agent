package tracers

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
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

const networkTraceName = "trace_network"

var _ containerwatcher.TracerInterface = (*NetworkTracer)(nil)

// NetworkTracer implements TracerInterface for events
type NetworkTracer struct {
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	kubeIPResolver     *kubeipresolver.KubeIPResolver
	kubeManager        *kskubemanager.KubeManager
	kubeNameResolver   *kubenameresolver.KubeNameResolver
	ociStore           *orasoci.ReadOnlyStore
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewNetworkTracer creates a new tracer
func NewNetworkTracer(
	kubeIPResolver *kubeipresolver.KubeIPResolver,
	kubeManager *kskubemanager.KubeManager,
	kubeNameResolver *kubenameresolver.KubeNameResolver,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *NetworkTracer {
	return &NetworkTracer{
		eventCallback:      eventCallback,
		kubeIPResolver:     kubeIPResolver,
		kubeManager:        kubeManager,
		kubeNameResolver:   kubeNameResolver,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the tracer
func (nt *NetworkTracer) Start(ctx context.Context) error {
	nt.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_tcp:v0.44.1",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			nt.kubeIPResolver,
			nt.kubeManager,
			nt.kubeNameResolver,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			nt.eventOperator(),
		),
		gadgetcontext.WithName(networkTraceName),
		gadgetcontext.WithOrasReadonlyTarget(nt.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.oci.annotate": "tracetcp:kubenameresolver.enable=true",
		}
		err := nt.runtime.RunGadget(nt.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", nt.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (nt *NetworkTracer) Stop() error {
	if nt.gadgetCtx != nil {
		nt.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (nt *NetworkTracer) GetName() string {
	return networkTraceName
}

// GetEventType returns the event type this tracer produces
func (nt *NetworkTracer) GetEventType() utils.EventType {
	return utils.NetworkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (nt *NetworkTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DNetwork {
		return false
	}
	return cfg.EnableNetworkTracing || cfg.EnableRuntimeDetection
}

func (nt *NetworkTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.NetworkEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					logger.L().Info("Matthias - event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					nt.callback(&utils.DatasourceEvent{Datasource: d, Data: data, EventType: utils.NetworkEventType})
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
func (nt *NetworkTracer) callback(event *utils.DatasourceEvent) {
	// do not skip dropped events as their processing is done in the worker

	//	nt.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	//	nt.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	//	if nt.kubeIPInstance != nil {
	//		_ = nt.kubeIPInstance.DatasourceEvent(event)
	//	}
	//	if nt.kubeNameInstance != nil {
	//		_ = nt.kubeNameInstance.DatasourceEvent(event)
	//	}

	if nt.eventCallback != nil {
		// Extract container ID and process ID from the network event
		containerID := event.GetContainerID()
		if containerID == "" {
			return
		}
		event.GetPort()
		event.GetProto()
		event.GetDstPort()

		nt.eventCallback(event, containerID, 0)
	}
}

// startKubernetesResolution starts the kubeIP and kube name resolution
//func (nt *NetworkTracer) startKubernetesResolution() error {
//	kubeIPOp := operators.GetRaw(kubeipresolver.OperatorName).(*kubeipresolver.KubeIPResolver)
//	_ = kubeIPOp.Init(nil)

//	kubeIPInstance, err := kubeIPOp.Instantiate(nil, nil, nil)
//	if err != nil {
//		return fmt.Errorf("creating kube ip resolver: %w", err)
//	}

//	nt.kubeIPInstance = kubeIPInstance
//	_ = nt.kubeIPInstance.PreGadgetRun()

//	kubeNameOp := operators.GetRaw(kubenameresolver.OperatorName).(*kubenameresolver.KubeNameResolver)
//	_ = kubeNameOp.Init(nil)
//	kubeNameInstance, err := kubeNameOp.Instantiate(nil, nil, nil)
//	if err != nil {
//		return fmt.Errorf("creating kube name resolver: %w", err)
//	}

//	nt.kubeNameInstance = kubeNameInstance
//	_ = nt.kubeNameInstance.PreGadgetRun()

//	return nil
//}
