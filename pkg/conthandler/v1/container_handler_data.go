package conthandler

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
)

type ContainerEventType string

type ContainerEventData struct {
	imageTAG       string
	container      *containercollection.Container
	wlid           string
	instanceID     instanceidhandler.IInstanceID
	k8sContainerID string
}

func CreateNewContainerEvent(imageTAG string, container *containercollection.Container, k8sContainerID, wlid string, instanceID instanceidhandler.IInstanceID) *ContainerEventData {
	return &ContainerEventData{
		imageTAG:       imageTAG,
		container:      container,
		wlid:           wlid,
		instanceID:     instanceID,
		k8sContainerID: k8sContainerID,
	}
}

func (event *ContainerEventData) GetK8SContainerID() string {
	return event.k8sContainerID
}

func (event *ContainerEventData) GetContainerID() string {
	return event.container.ID
}

func (event *ContainerEventData) GetK8SWorkloadID() string {
	return event.wlid
}

func (event *ContainerEventData) GetContainerName() string {
	return event.container.Name
}

func (event *ContainerEventData) GetInstanceID() instanceidhandler.IInstanceID {
	return event.instanceID
}

func (event *ContainerEventData) GetInstanceIDHash() string {
	return event.instanceID.GetHashed()
}

func (event *ContainerEventData) GetImageTAG() string {
	return event.imageTAG
}

func (event *ContainerEventData) GetNamespace() string {
	return event.container.Namespace
}

func (event *ContainerEventData) GetPodName() string {
	return event.container.Podname
}

func (event *ContainerEventData) GetContainer() *containercollection.Container {
	return event.container
}
