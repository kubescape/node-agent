package conthandler

type ContainerAggregatorClient interface {
	StartAggregate(chan error) error
	StopAggregate() error
	GetContainerRealtimeFileList() map[string]bool
}
