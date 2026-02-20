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
	kubeletTLSImageName = "kubelet_tls:latest"
	kubeletTLSTraceName = "trace_kubelet_tls"
)

var _ containerwatcher.TracerInterface = (*KubeletTLSTracer)(nil)

// KubeletTLSTracer implements TracerInterface for kubelet TLS events
type KubeletTLSTracer struct {
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   operators.DataOperator
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime
}

// NewKubeletTLSTracer creates a new tracer
func NewKubeletTLSTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
) *KubeletTLSTracer {
	return &KubeletTLSTracer{
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// Start initializes and starts the tracer
func (t *KubeletTLSTracer) Start(ctx context.Context) error {
	t.gadgetCtx = gadgetcontext.New(
		ctx,
		kubeletTLSImageName,
		gadgetcontext.WithDataOperators(
			t.kubeManager,
			ocihandler.OciHandler,
			t.eventOperator(),
		),
		gadgetcontext.WithName(kubeletTLSTraceName),
		gadgetcontext.WithOrasReadonlyTarget(t.ociStore),
	)
	go func() {
		params := map[string]string{
			"operator.LocalManager.host": "true",
		}
		err := t.runtime.RunGadget(t.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", t.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	return nil
}

// Stop gracefully stops the tracer
func (t *KubeletTLSTracer) Stop() error {
	if t.gadgetCtx != nil {
		t.gadgetCtx.Cancel()
	}
	return nil
}

// GetName returns the unique name of the tracer
func (t *KubeletTLSTracer) GetName() string {
	return kubeletTLSTraceName
}

// GetEventType returns the event type this tracer produces
func (t *KubeletTLSTracer) GetEventType() utils.EventType {
	return utils.KubeletTLSEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (t *KubeletTLSTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DKubeletTLS && cfg.EnableRuntimeDetection
}

func (t *KubeletTLSTracer) eventOperator() operators.DataOperator {
	return simple.New(string(utils.KubeletTLSEventType),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					t.callback(&utils.DatasourceEvent{Datasource: d, Data: source.DeepCopy(data), EventType: utils.KubeletTLSEventType})
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
func (t *KubeletTLSTracer) callback(event utils.KubeletTLSEvent) {
	if t.eventCallback != nil {
		containerID := event.GetContainerID()
		processID := event.GetPID()
		t.eventCallback(event, containerID, processID)
	}
}
