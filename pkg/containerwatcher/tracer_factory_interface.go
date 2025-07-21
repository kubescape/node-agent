package containerwatcher

// TracerRegistrar defines the interface for registering tracers
type TracerRegistrar interface {
	RegisterTracer(tracer TracerInterface)
}

// TracerFactoryInterface defines the interface for creating tracers
type TracerFactoryInterface interface {
	CreateAllTracers(manager TracerRegistrar)
}
