package containerwatcher

import (
	"fmt"

	tracersyscalls "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"
	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) startSyscallTracing() error {
	if err := ch.tracerCollection.AddTracer(syscallsTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	go func() {
		for event := range ch.syscallsWorkerChan {
			ch.syscallsWorkerPool.Invoke(*event)
		}
	}()

	syscallTracer, err := tracersyscalls.NewTracer(ch.containerCollection, nil)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	ch.syscallTracer = syscallTracer
	ch.syscallTracer.SetEventHandler(ch.syscallEventCallback)

	return nil
}

func (ch *IGContainerWatcher) syscallEventCallback(event *tracersyscallstype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("syscall tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.syscallsWorkerChan <- event
}

func (ch *IGContainerWatcher) stopSystemcallTracing() error {
	// Stop seccomp tracer
	ch.syscallTracer.Stop()
	return nil
}
