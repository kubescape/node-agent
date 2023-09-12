package containerwatcher

import (
	"fmt"

	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
)

func (ch *IGContainerWatcher) startSystemcallTracing() error {
	// Add seccomp tracer
	syscallTracer, err := tracerseccomp.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.syscallTracer = syscallTracer
	return nil
}

func (ch *IGContainerWatcher) stopSystemcallTracing() error {
	// Stop seccomp tracer
	ch.syscallTracer.Close()
	return nil
}
