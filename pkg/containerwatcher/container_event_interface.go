package containerwatcher

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
)

type ContainerEvent interface {
	GetContainer() *containercollection.Container
	GetContainerID() string
	GetContainerName() string
	GetImageID() string
	GetImageTAG() string
	GetInstanceID() instanceidhandler.IInstanceID
	GetInstanceIDHash() string
	GetK8SContainerID() string
	GetK8SWorkloadID() string
	GetNamespace() string
	GetPodName() string
}
