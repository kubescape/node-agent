package conthandler

import (
	"fmt"
	"strings"

	instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler"
)

const (
	ContainerRunning = "Running"
	ContainerDeleted = "Deleted"
)

type ContainerEventType string

type ContainerEventData struct {
	imageID       string
	containerID   string
	containerName string
	wlid          string
	instanceID    instanceidhandler.IInstanceID
	eventType     ContainerEventType
}

func CreateNewContainerEvent(imageID, containerID, containerName, wlid string, instanceID instanceidhandler.IInstanceID, eventType ContainerEventType) *ContainerEventData {
	return &ContainerEventData{
		imageID:       imageID,
		containerID:   containerID,
		containerName: containerName,
		wlid:          wlid,
		instanceID:    instanceID,
		eventType:     eventType,
	}
}

func (event *ContainerEventData) GetContainerEventType() ContainerEventType {
	return event.eventType
}

func (event *ContainerEventData) GetContainerID() string {
	return event.containerID
}

func (event *ContainerEventData) GetK8SWorkloadID() string {
	return event.wlid
}

func (event *ContainerEventData) GetContainerName() string {
	return event.containerName
}

func (event *ContainerEventData) GetImageHash() (string, error) {
	imageIDSplit := strings.Split(event.imageID, "@sha256:")
	if len(imageIDSplit) == 2 {
		return imageIDSplit[1], nil
	}
	return "", fmt.Errorf("GetImageHash: fail to parse image hash of image ID %s", event.imageID)
}

func (event *ContainerEventData) GetImageID() string {
	return event.imageID
}

func (event *ContainerEventData) GetInstanceID() instanceidhandler.IInstanceID {
	return event.instanceID
}

func (event *ContainerEventData) GetInstanceIDHash() string {
	return event.instanceID.GetHashed()
}
