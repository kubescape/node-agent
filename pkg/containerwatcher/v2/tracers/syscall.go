package tracers

import (
	"context"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
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

	// defaultSyscallPollInterval is used when cfg.SyscallPollInterval is unset (e.g. tests
	// constructing config.Config directly). It matches the config package's own default.
	defaultSyscallPollInterval = 2 * time.Second
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
}

// NewSyscallTracer creates a new tracer
func NewSyscallTracer(
	kubeManager operators.DataOperator,
	runtime runtime.Runtime,
	ociStore *orasoci.ReadOnlyStore,
	eventCallback containerwatcher.ResultCallback,
	cfg config.Config,
) *SyscallTracer {
	return &SyscallTracer{
		cfg:           cfg,
		eventCallback: eventCallback,
		kubeManager:   kubeManager,
		ociStore:      ociStore,
		runtime:       runtime,
	}
}

// pollInterval returns the configured eBPF map-fetch interval for the advise_seccomp map,
// falling back to defaultSyscallPollInterval when unset. A long interval widens the window in
// which a terminating container's last syscalls are never fetched before its profile is saved
// and its data discarded (kubescape/node-agent#922), so this is kept short by default.
func (st *SyscallTracer) pollInterval() time.Duration {
	if st.cfg.SyscallPollInterval > 0 {
		return st.cfg.SyscallPollInterval
	}
	return defaultSyscallPollInterval
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
	go func() {
		params := map[string]string{
			"operator.oci.ebpf.map-fetch-count":    "0",
			"operator.oci.ebpf.map-fetch-interval": st.pollInterval().String(),
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

	syscallsBuffer := event.GetSyscalls()
	for _, syscall := range decodeSyscalls(syscallsBuffer) {
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
	syscallStrings := make([]string, 0)
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
