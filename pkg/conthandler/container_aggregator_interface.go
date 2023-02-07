package conthandler

type ContainerAggregatorClient interface {
	StartAggregate(containerID string) error
	StopAggregate(containerID string) error
	ListContainerRealTimeFiles(containerID string) []string
}
