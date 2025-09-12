package tracers

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

const syscallTraceName = "syscall_tracer"

var _ containerwatcher.TracerInterface = (*SyscallTracer)(nil)

// SyscallTracer implements TracerInterface for syscall/seccomp events
type SyscallTracer struct {
	//tracer                  *tracerseccomp.Tracer
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient
	ruleManager             rulemanager.RuleManagerClient
}

// NewSyscallTracer creates a new syscall tracer
func NewSyscallTracer(containerProfileManager containerprofilemanager.ContainerProfileManagerClient, ruleManager rulemanager.RuleManagerClient) *SyscallTracer {
	return &SyscallTracer{
		containerProfileManager: containerProfileManager,
		ruleManager:             ruleManager,
	}
}

// Start initializes and starts the syscall tracer
func (st *SyscallTracer) Start(ctx context.Context) error {
	// Create seccomp tracer
	//syscallTracer, err := tracerseccomp.NewTracer()
	//if err != nil {
	//	return fmt.Errorf("creating syscall tracer: %w", err)
	//}

	//st.tracer = syscallTracer

	// Register peek function with managers
	//st.registerPeekFunction()

	return nil
}

// Stop gracefully stops the syscall tracer
func (st *SyscallTracer) Stop() error {
	//if st.tracer != nil {
	//	st.tracer.Close()
	//}
	return nil
}

// GetName returns the unique name of the tracer
func (st *SyscallTracer) GetName() string {
	return "syscall_tracer"
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

// Peek provides the peek function for other components
func (st *SyscallTracer) Peek(mntns uint64) ([]string, error) {
	//if st.tracer != nil {
	//	return st.tracer.Peek(mntns)
	//}
	return nil, fmt.Errorf("syscall tracer not started")
}

// registerPeekFunction registers the peek function with the required managers
func (st *SyscallTracer) registerPeekFunction() {
	if st.containerProfileManager != nil {
		st.containerProfileManager.RegisterPeekFunc(st.Peek)
	}
	if st.ruleManager != nil {
		st.ruleManager.RegisterPeekFunc(st.Peek)
	}
}

// SetPeekFunc sets the peek function (kept for compatibility, but not used since we directly use tracer.Peek)
func (st *SyscallTracer) SetPeekFunc(peekFunc func(mntns uint64) ([]string, error)) {
	// This method is kept for compatibility but not used since we directly use st.tracer.Peek
}
