package tracers

import (
	"context"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpfoperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const (
	syscallImageName = "ghcr.io/inspektor-gadget/gadget/advise_seccomp:v0.48.1"
	syscallTraceName = "syscall_tracer"

	// syscallDataSourceName is the advise_seccomp gadget's map-iterator datasource name
	// (see TestSyscallFields). Peek uses it to target only this tracer's map iterator.
	syscallDataSourceName = "syscalls"
)

var _ containerwatcher.TracerInterface = (*SyscallTracer)(nil)

// SyscallTracer implements TracerInterface for events
type SyscallTracer struct {
	cfg           config.Config
	eventCallback containerwatcher.ResultCallback
	gadgetCtx     *gadgetcontext.GadgetContext
	kubeManager   operators.DataOperator
	ociStore      *orasoci.ReadOnlyStore
	runtime       runtime.Runtime

	// reportSyscalls is called once per fetch with the whole decoded batch for a container,
	// bypassing the generic per-event pipeline entirely for this consumer (see callback and
	// ContainerProfileManagerClient.ReportSyscalls, kubescape/node-agent#922).
	reportSyscalls func(containerID string, syscalls []string)

	// done is closed by Stop to stop the periodic Peek loop started in Start.
	done chan struct{}
}

// NewSyscallTracer creates a new tracer
func NewSyscallTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	cfg config.Config,
	reportSyscalls func(containerID string, syscalls []string),
) *SyscallTracer {
	return &SyscallTracer{
		cfg:            cfg,
		eventCallback:  eventCallback,
		kubeManager:    kubeManager,
		ociStore:       ociStore,
		runtime:        runtime,
		reportSyscalls: reportSyscalls,
	}
}

// pollInterval returns the configured cadence at which Start's background loop calls Peek,
// falling back to config.DefaultSyscallPollInterval when unset.
func (st *SyscallTracer) pollInterval() time.Duration {
	if st.cfg.SyscallPollInterval > 0 {
		return st.cfg.SyscallPollInterval
	}
	return config.DefaultSyscallPollInterval
}

// Peek requests an immediate, out-of-band fetch of the advise_seccomp eBPF map. It does not
// block until the fetch completes or until any resulting events have been processed by this
// tracer's eventCallback — callers needing that must wait separately afterward.
//
// The gadget instance itself runs with no internal fetch schedule (see Start); every fetch,
// periodic or not, goes through this one call. Start's own background loop calls it on
// pollInterval for live event delivery (profile-building and rule-based alerting alike), and
// ContainerProfileManager calls it once more, out of that schedule, right before it stops
// tracking a container (on termination or max-sniffing-time) to recover that container's last
// syscalls before they become unreachable (kubescape/node-agent#922).
func (st *SyscallTracer) Peek() {
	ebpfoperator.TriggerManualMapFetch(syscallDataSourceName)
}

// Start initializes and starts the tracer
func (st *SyscallTracer) Start(ctx context.Context) error {
	st.gadgetCtx = gadgetcontext.New(
		ctx,
		// This is the image that contains the gadget we want to run.
		syscallImageName,
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			st.kubeManager,
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			st.eventOperator(),
		),
		gadgetcontext.WithName(syscallTraceName),
		gadgetcontext.WithOrasReadonlyTarget(st.ociStore),
	)
	st.done = make(chan struct{})
	go func() {
		// map-fetch-interval "0" together with map-fetch-count "0" (unlimited) disables the
		// gadget's own internal fetch schedule entirely: every fetch is driven by Peek instead
		// (see the loop below and Peek's doc comment).
		params := map[string]string{
			"operator.oci.ebpf.map-fetch-count":    "0",
			"operator.oci.ebpf.map-fetch-interval": "0",
		}
		err := st.runtime.RunGadget(st.gadgetCtx, nil, params)
		if err != nil {
			logger.L().Error("Error running gadget", helpers.String("gadget", st.gadgetCtx.Name()), helpers.Error(err))
		}
	}()
	go st.runPeekLoop()
	return nil
}

// runPeekLoop calls Peek every pollInterval until Stop closes st.done.
func (st *SyscallTracer) runPeekLoop() {
	ticker := time.NewTicker(st.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-st.done:
			return
		case <-ticker.C:
			st.Peek()
		}
	}
}

// Stop gracefully stops the tracer
func (st *SyscallTracer) Stop() error {
	if st.gadgetCtx != nil {
		st.gadgetCtx.Cancel()
	}
	if st.done != nil {
		close(st.done)
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
				err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					st.callback(&utils.DatasourceEvent{Datasource: d, Data: source.DeepCopy(data), EventType: utils.SyscallEventType})
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
func (st *SyscallTracer) callback(event *utils.DatasourceEvent) {
	containerID := event.GetContainerID()
	processID := event.GetPID()

	syscallList := decodeSyscalls(event.GetSyscalls())
	if len(syscallList) == 0 {
		event.Release()
		return
	}

	// The map covers every mount namespace on the node, including ones not (yet, or ever)
	// resolved to a container - e.g. host processes. reportSyscalls is called directly,
	// bypassing the generic per-event pipeline, so an empty containerID must be skipped
	// explicitly here rather than relying on that pipeline's own check.
	//
	// Report the whole batch directly, bypassing the generic per-event pipeline entirely for
	// this consumer (see reportSyscalls' doc comment). Dispatched on its own goroutine so a
	// slow or momentarily-blocked container (e.g. withContainer's SyncChannel send on a
	// profile-size-split signal) can never stall this callback, which the gadget's shared
	// fetch-processing goroutine calls synchronously for every currently traced container.
	if containerID != "" {
		go st.reportSyscalls(containerID, syscallList)
	}

	// eventCallback must run for EVERY decoded syscall regardless of containerID -- unlike
	// reportSyscalls, this is a caller-supplied callback, and not every consumer of this
	// tracer drops empty-containerID events itself. node-agent's own EventHandlerFactory.
	// ProcessEvent still does (its own empty-ContainerID check), so routing these events to
	// it costs node-agent nothing functionally; other consumers that watch non-containerized
	// host processes (which have containerID=="") depend on actually receiving these events
	// here. (Fixed: a prior version of this function early-returned on containerID=="" before
	// this loop ever ran, silently dropping all host-process syscall events for any consumer
	// whose eventCallback doesn't already filter them -- see
	// armosec/private-node-agent#548's review.)
	for _, syscall := range syscallList {
		st.eventCallback(&utils.DatasourceEvent{
			Data:       event.Datasource.DeepCopy(event.Data),
			Datasource: event.Datasource,
			EventType:  event.EventType,
			Syscall:    syscall,
		}, containerID, processID)
	}
	// Release the original deep-copied data since each sub-event now has its own copy
	event.Release()
}

func decodeSyscalls(syscallsBuffer []byte) []string {
	syscallStrings := make([]string, 0, len(syscallsBuffer))
	// Syscall numbers this build cannot resolve to a name are skipped. Recording a
	// placeholder name would propagate into the application profile and from there
	// into generated seccomp profiles, where it is not a valid syscall name. The
	// numbers are collected and logged once per decode to keep this loop cheap.
	var skipped []int
	for i := range syscallsBuffer {
		if syscallsBuffer[i] > 0 {
			syscallName, exist := syscalls.GetSyscallNameByNumber(i)
			if !exist {
				skipped = append(skipped, i)
				continue
			}
			syscallStrings = append(syscallStrings, syscallName)
		}
	}
	if len(skipped) > 0 {
		logger.L().Debug("decodeSyscalls - skipped syscall numbers with no known name",
			helpers.String("syscallNumbers", fmt.Sprint(skipped)))
	}
	return syscallStrings
}
