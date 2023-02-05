package conthandler

type ContainerAggregatorClient interface {
	StartAggregate() error
	StopAggregate() error
	GetContainerRealtimeFileList() []string
}
