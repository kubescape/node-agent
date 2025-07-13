package tracers

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
)

const syscallTraceName = "syscall_tracer"

// SyscallTracer implements TracerInterface for syscall/seccomp events
type SyscallTracer struct {
	peekFunc func(mntns uint64) ([]string, error)
}

// NewSyscallTracer creates a new syscall tracer
func NewSyscallTracer() *SyscallTracer {
	return &SyscallTracer{}
}

// Start initializes and starts the syscall tracer
func (st *SyscallTracer) Start(ctx context.Context) error {
	// The syscall tracer doesn't need to be added to tracer collection
	// It just provides a Peek function for other components
	return nil
}

// Stop gracefully stops the syscall tracer
func (st *SyscallTracer) Stop() error {
	// Nothing to stop for syscall tracer
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
func (st *SyscallTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableRuntimeDetection || config.EnableSeccomp
	}
	return false
}

// Peek provides the peek function for other components
func (st *SyscallTracer) Peek(mntns uint64) ([]string, error) {
	if st.peekFunc != nil {
		return st.peekFunc(mntns)
	}
	return nil, fmt.Errorf("peek function not set")
}

// SetPeekFunc sets the peek function
func (st *SyscallTracer) SetPeekFunc(peekFunc func(mntns uint64) ([]string, error)) {
	st.peekFunc = peekFunc
}
