package hostwatcher

import (
	"fmt"

	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
)

func (ch *IGHostWatcher) startSystemcallTracing() error {
	// Add seccomp tracer
	syscallTracer, err := tracerseccomp.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.syscallTracer = syscallTracer
	// Register peek func for application profile manager
	ch.ruleManager.RegisterPeekFunc(ch.syscallTracer.Peek)

	return nil
}

func (ch *IGHostWatcher) stopSystemcallTracing() error {
	// Stop seccomp tracer
	ch.syscallTracer.Close()
	return nil
}
