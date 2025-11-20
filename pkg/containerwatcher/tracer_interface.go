package containerwatcher

import (
	"context"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
)

// TracerInterface defines the common interface for all eBPF tracers
type TracerInterface interface {
	// Start initializes and starts the tracer
	Start(ctx context.Context) error

	// Stop gracefully stops the tracer
	Stop() error

	// GetName returns the unique name of the tracer
	GetName() string

	// GetEventType returns the event type this tracer produces
	GetEventType() utils.EventType

	// IsEnabled checks if this tracer should be enabled based on configuration
	IsEnabled(cfg config.Config) bool
}
