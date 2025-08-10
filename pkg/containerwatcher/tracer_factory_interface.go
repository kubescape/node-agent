package containerwatcher

type TracerRegistrer interface {
	RegisterTracer(tracer TracerInterface)
}

type TracerFactoryInterface interface {
	CreateAllTracers(manager TracerRegistrer)
}
