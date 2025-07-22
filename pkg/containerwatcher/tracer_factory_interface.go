package containerwatcher

import "context"

// TracerRegistrer defines the interface for registering tracers
type TracerRegistrer interface {
	RegisterTracer(tracer TracerInterface)
}

// TracerFactoryInterface defines the interface for creating tracers
type TracerFactoryInterface interface {
	CreateAllTracers(manager TracerRegistrer)
	StartThirdPartyTracers(ctx context.Context) error
	StopThirdPartyTracers()
}
