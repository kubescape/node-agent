package conthandler

import (
	conthandlerV1 "node-agent/pkg/conthandler/v1"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"k8s.io/client-go/rest"
)

type ContainerClient interface {
	GetK8sConfig() *rest.Config
	CalculateWorkloadParentRecursive(workload any) (string, string, error)
	GetWorkload(namespace, kind, name string) (any, error)
	GenerateWLID(workload any, clusterName string) string
}

type ContainerWatcherClient interface {
	GetContainerClient() ContainerClient
	GetNodeName() string
	ParsePodData(*workloadinterface.Workload, *containercollection.Container) (*conthandlerV1.ContainerEventData, error)
}
