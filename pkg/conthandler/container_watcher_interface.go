package conthandler

import (
	v1 "sniffer/pkg/conthandler/v1"

	"k8s.io/apimachinery/pkg/watch"
)

type ContainerClient interface {
	GetWatcher() (watch.Interface, error)
	CalculateWorkloadParentRecursive(workload any) (string, string, error)
	GetWorkload(namespace, kind, name string) (any, error)
	GetApiVersion(workload any) string
	GenerateWLID(workload any, clusterName string) string
}

type ContainerWatcherClient interface {
	StartWatchedOnContainers(contClient ContainerClient, containerEventChannel chan v1.ContainerEventData) error
}
