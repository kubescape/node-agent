package conthandler

type ContainerAggregatorClient interface {
	StartAggregate() error
	StopAggregate() error
	ListContainerRealTimeFiles() []string
}
