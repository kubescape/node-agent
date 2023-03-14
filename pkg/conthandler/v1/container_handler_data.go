package conthandler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	ContainerRunning = "Running"
	ContainerDeleted = "Deleted"
)

type ContainerEventType string

type ContainerEventData struct {
	imageID     string
	containerID string
	podName     string
	wlid        string
	instanceID  string
	eventType   ContainerEventType
}

func CreateNewContainerEvent(imageID, containerID, podName, wlid, instanceID string, eventType ContainerEventType) *ContainerEventData {
	return &ContainerEventData{
		imageID:     imageID,
		containerID: containerID,
		podName:     podName,
		wlid:        wlid,
		instanceID:  instanceID,
		eventType:   eventType,
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

func (event *ContainerEventData) GetInstanceID() string {
	return event.instanceID
}

func (event *ContainerEventData) GetInstanceIDHash() string {
	hash := sha256.Sum256([]byte(event.instanceID))
	str := hex.EncodeToString(hash[:])
	return str
}

func CreateInstanceID(apiVersion, resourceVersion, wlid, containerName string) (string, error) {
	temp := wlid[strings.Index(wlid, "namespace-")+len("namespace-"):]
	namespace := temp[:strings.Index(temp, "/")]
	kind := temp[strings.Index(temp, "/")+1 : strings.Index(temp, "-")]
	name := temp[strings.Index(temp, "-")+1:]

	return "apiVersion-" + apiVersion + "/namespace-" + namespace + "/kind-" + kind + "/name-" + name + "/resourceVersion-" + resourceVersion + "/containerName-" + containerName, nil
}
