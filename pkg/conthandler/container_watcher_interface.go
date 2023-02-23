package conthandler

import (
	v1 "sniffer/pkg/conthandler/v1"

	"k8s.io/apimachinery/pkg/watch"
)

type ContainerClient interface {
	GetWatcher() (watch.Interface, error)
}

type ContainerWatcherClient interface {
	StartWatchedOnContainers(contClient ContainerClient, containerEventChannel chan v1.ContainerEventData) error
}
