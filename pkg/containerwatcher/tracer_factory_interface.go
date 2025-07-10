package containerwatcher

// TracerFactoryInterface defines the interface for creating tracers
type TracerFactoryInterface interface {
	CreateAllTracers(manager *TracerManager)
}
