package containerwatcher

import (
	"node-agent/pkg/containerwatcher"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler"
)

type ContainerEventData struct {
	container      *containercollection.Container
	imageID        string
	imageTAG       string
	k8sContainerID string
	wlid           string
	instanceID     instanceidhandler.IInstanceID
}

var _ containerwatcher.ContainerEvent = (*ContainerEventData)(nil)

func CreateNewContainerEvent(container *containercollection.Container, imageID, imageTAG, k8sContainerID, wlid string, instanceID instanceidhandler.IInstanceID) *ContainerEventData {
	return &ContainerEventData{
		container:      container,
		imageID:        imageID,
		imageTAG:       imageTAG,
		k8sContainerID: k8sContainerID,
		wlid:           wlid,
		instanceID:     instanceID,
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

func (event *ContainerEventData) GetImageID() string {
	return event.imageID
}
