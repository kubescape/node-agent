package conthandler

import (
	"strings"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

const (
	CONTAINER_RUNNING = "Running"
	CONTAINER_DELETED = "Deleted"
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

func CreateInstanceID(workload *workloadinterface.Workload, wlid string, containerName string) string {
	temp := wlid[strings.Index(wlid, "namespace-")+len("namespace-"):]
	kind := temp[strings.Index(temp, "/")+1 : strings.Index(temp, "-")]
	name := temp[strings.Index(temp, "-")+1:]

	return "apiVersion-" + workload.GetApiVersion() + "/namespace-" + workload.GetNamespace() + "/kind-" + kind + "/name-" + name + "/resourceVersion-" + workload.GetResourceVersion() + "/containerName-" + containerName
}
