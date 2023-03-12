package conthandler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

const (
	ContainerRunning = "Running"
	ContainerDeleted = "Deleted"
)

type ContainerEventType string

type k8sTripletIdentity struct {
	namespace       string
	k8sAncestorType string
	name            string
}

type handledContainer struct {
	// containerAggregator       *aggregator.Aggregator
	containerAggregatorStatus    bool
	containerAggregatorStartTime *time.Time
	snifferTimer                 *time.Timer
	syncChannel                  map[string]chan error
	containerEvent               ContainerEventData
}

type afterTimerActionsData struct {
	containerID string
	service     string
}

type ContainerHandler struct {
	watchedContainers        map[string]*handledContainer
	afterTimerActionsChannel chan afterTimerActionsData
}

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

func isWLIDInExpectedFormat(wlid string) bool {
	if !strings.HasPrefix(wlid, "wlid://cluster-") {
		return false
	}
	trimmedStr := strings.TrimPrefix(wlid, "wlid://cluster-")
	namespaceIndex := strings.Index(trimmedStr, "/namespace-")
	if namespaceIndex == -1 {
		return false
	}
	trimmedStr2 := trimmedStr[namespaceIndex+len("/namespace-"):]
	spiltStrings := strings.Split(trimmedStr2, "/")
	if len(spiltStrings) != 2 {
		return false
	}
	kindAndName := strings.Split(spiltStrings[1], "-")
	if len(kindAndName) < 2 {
		return false
	}

	return true
}

func CreateInstanceID(workload *workloadinterface.Workload, wlid string, containerName string) (string, error) {
	if !isWLIDInExpectedFormat(wlid) {
		return "", fmt.Errorf("WLID is not in the expected format: format: wlid://cluster-<name>/namespace-<name>/<kind>-<name>, wlid: %s", wlid)
	}

	temp := wlid[strings.Index(wlid, "namespace-")+len("namespace-"):]
	kind := temp[strings.Index(temp, "/")+1 : strings.Index(temp, "-")]
	name := temp[strings.Index(temp, "-")+1:]

	return "apiVersion-" + workload.GetApiVersion() + "/namespace-" + workload.GetNamespace() + "/kind-" + kind + "/name-" + name + "/resourceVersion-" + workload.GetResourceVersion() + "/containerName-" + containerName, nil
}
