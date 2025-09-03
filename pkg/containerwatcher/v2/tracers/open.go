package tracers

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const openTraceName = "trace_open"

var _ containerwatcher.TracerInterface = (*OpenTracer)(nil)

// OpenTracer implements TracerInterface for open events
type OpenTracer struct {
	cfg                config.Config
	containerSelector  containercollection.ContainerSelector
	eventCallback      containerwatcher.ResultCallback
	gadgetCtx          *gadgetcontext.GadgetContext
	ociStore           *orasoci.ReadOnlyStore
	orderedEventQueue  EventQueueInterface
	runtime            runtime.Runtime
	thirdPartyEnricher containerwatcher.TaskBasedEnricher
}

// NewOpenTracer creates a new open tracer
func NewOpenTracer(
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *OpenTracer {
	return &OpenTracer{
		containerSelector:  containerSelector,
		eventCallback:      eventCallback,
		ociStore:           ociStore,
		runtime:            runtime,
		thirdPartyEnricher: thirdPartyEnricher,
	}
}

// Start initializes and starts the open tracer
func (ot *OpenTracer) Start(ctx context.Context) error {
	ot.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_open:v0.40.0",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			KubeManager,
			//KubeNameResolver,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			ot.openEventOperator(),
		),
		gadgetcontext.WithName(openTraceName),
		gadgetcontext.WithOrasReadonlyTarget(ot.ociStore),
	)
	go func() {
		err := ot.runtime.RunGadget(ot.gadgetCtx, nil, nil)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", ot.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the open tracer
func (ot *OpenTracer) Stop() error {
	if ot.gadgetCtx != nil {
		ot.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (ot *OpenTracer) GetName() string {
	return openTraceName
}

// GetEventType returns the event type this tracer produces
func (ot *OpenTracer) GetEventType() utils.EventType {
	return utils.OpenEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ot *OpenTracer) IsEnabled(cfg config.Config) bool {
	ot.cfg = cfg
	if cfg.DOpen {
		return false
	}
	return cfg.EnableApplicationProfile || cfg.EnableRuntimeDetection
}

func (ot *OpenTracer) openEventOperator() operators.DataOperator {
	return simple.New(string(utils.OpenEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),
					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)
				pidF := d.GetField("proc.pid")
				commF := d.GetField("proc.comm")
				fnameF := d.GetField("fname")
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					// TODO add more fields
					processID, _ := pidF.Uint32(data)
					comm, _ := commF.String(data)
					fname, _ := fnameF.String(data)
					event := &traceropentype.Event{
						Pid:      processID,
						Comm:     comm,
						FullPath: fname,
					}
					logger.L().Info("Matthias - event received", helpers.String("data", string(jsonFormatter.Marshal(data))))
					ot.openEventCallback(event)
					return nil
				}, opPriority)
				if err != nil {
					return err
				}
			}
			return nil
		}),
	)
}

// openEventCallback handles open events from the tracer
func (ot *OpenTracer) openEventCallback(event *traceropentype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if ot.cfg.EnableFullPathTracing {
		event.Path = event.FullPath
	}

	if event.K8s.ContainerName == "" {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		return
	}

	if event.Err > -1 && event.FullPath != "" {
		openEvent := &events.OpenEvent{Event: *event}
		// Handle the event with syscall enrichment
		ot.handleEvent(openEvent, []uint64{SYS_OPEN, SYS_OPENAT})
	}
}

// handleEvent processes the event with syscall enrichment
func (ot *OpenTracer) handleEvent(event *events.OpenEvent, syscalls []uint64) {
	if ot.eventCallback != nil {
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		EnrichEvent(ot.thirdPartyEnricher, event, syscalls, ot.eventCallback, containerID, processID)
	}
}
