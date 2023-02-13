package conthandler

type ContainerWatcherClient interface {
	StartWatchedOnNewContainers() error
}
