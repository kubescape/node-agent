package conthandler

type containerWatcherClient interface {
	StartWatchedOnNewContainers()
}
