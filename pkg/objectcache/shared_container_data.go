package objectcache

import (
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type ContainerType int

const (
	// ContainerType represents the type of container in a pod
	Unknown = iota
	Container
	InitContainer
	EphemeralContainer
)

type WatchedContainerStatus string

const (
	// WatchedContainerStatus represents the status of a watched container
	WatchedContainerStatusInitializing WatchedContainerStatus = helpersv1.Initializing
	WatchedContainerStatusReady        WatchedContainerStatus = helpersv1.Learning
	WatchedContainerStatusCompleted    WatchedContainerStatus = helpersv1.Completed

	WatchedContainerStatusMissingRuntime WatchedContainerStatus = helpersv1.MissingRuntime
	WatchedContainerStatusTooLarge       WatchedContainerStatus = helpersv1.TooLarge
)

type WatchedContainerCompletionStatus string

const (
	// WatchedContainerCompletionStatus represents the completion status of a watched container
	WatchedContainerCompletionStatusPartial WatchedContainerCompletionStatus = helpersv1.Partial
	WatchedContainerCompletionStatusFull    WatchedContainerCompletionStatus = helpersv1.Full
)

func (c ContainerType) String() string {
	return [...]string{"unknown", "containers", "initContainers", "ephemeralContainers"}[c]
}

type WatchedContainerData struct {
	InstanceID                                 instanceidhandler.IInstanceID
	UpdateDataTicker                           *time.Ticker
	SyncChannel                                chan error
	RelevantRealtimeFilesByIdentifier          map[string]bool
	RelevantRelationshipsArtifactsByIdentifier map[string]bool
	RelevantArtifactsFilesByIdentifier         map[string]bool
	ParentResourceVersion                      string
	ContainerID                                string
	ImageTag                                   string
	ImageID                                    string
	Wlid                                       string
	K8sContainerID                             string
	ContainerType                              ContainerType
	ContainerIndex                             int
	ContainerInfos                             map[ContainerType][]ContainerInfo
	NsMntId                                    uint64
	InitialDelayExpired                        bool
	statusUpdated                              bool
	status                                     WatchedContainerStatus
	completionStatus                           WatchedContainerCompletionStatus
	ParentWorkloadSelector                     *metav1.LabelSelector
	SeccompProfilePath                         *string
	PreRunningContainer                        bool
	SeriesID                                   string
	PreviousReportTimestamp                    time.Time
	CurrentReportTimestamp                     time.Time
}

type ContainerInfo struct {
	Name     string
	ImageTag string
	ImageID  string
}

func GetLabels(watchedContainer *WatchedContainerData, stripContainer bool) map[string]string {
	labels := watchedContainer.InstanceID.GetLabels()
	for i := range labels {
		if labels[i] == "" {
			delete(labels, i)
		} else if stripContainer && i == helpersv1.ContainerNameMetadataKey {
			delete(labels, i)
		} else {
			if i == helpersv1.KindMetadataKey {
				labels[i] = wlid.GetKindFromWlid(watchedContainer.Wlid)
			} else if i == helpersv1.NameMetadataKey {
				labels[i] = wlid.GetNameFromWlid(watchedContainer.Wlid)
			}
			errs := validation.IsValidLabelValue(labels[i])
			if len(errs) != 0 {
				logger.L().Debug("GetLabels - label is not valid", helpers.String("label", labels[i]))
				for j := range errs {
					logger.L().Debug("GetLabels - label err description", helpers.String("Err: ", errs[j]))
				}
				delete(labels, i)
			}
		}
	}
	if watchedContainer.ParentResourceVersion != "" {
		labels[helpersv1.ResourceVersionMetadataKey] = watchedContainer.ParentResourceVersion
	}
	return labels
}

func (watchedContainer *WatchedContainerData) GetStatus() WatchedContainerStatus {
	return watchedContainer.status
}

func (watchedContainer *WatchedContainerData) GetCompletionStatus() WatchedContainerCompletionStatus {
	return watchedContainer.completionStatus
}

func (watchedContainer *WatchedContainerData) SetStatus(newStatus WatchedContainerStatus) {
	if newStatus != watchedContainer.status {
		watchedContainer.status = newStatus
		watchedContainer.statusUpdated = true
	}
}

func (watchedContainer *WatchedContainerData) SetCompletionStatus(newStatus WatchedContainerCompletionStatus) {
	if newStatus != watchedContainer.completionStatus {
		watchedContainer.completionStatus = newStatus
		watchedContainer.statusUpdated = true
	}
}

func (watchedContainer *WatchedContainerData) ResetStatusUpdatedFlag() {
	watchedContainer.statusUpdated = false
}

func (watchedContainer *WatchedContainerData) StatusUpdated() bool {
	return watchedContainer.statusUpdated
}

func (watchedContainer *WatchedContainerData) SetContainerInfo(wl workloadinterface.IWorkload, containerName string) error {
	podSpec, err := wl.GetPodSpec()
	if err != nil {
		return fmt.Errorf("failed to get pod spec: %w", err)
	}
	podStatus, err := wl.GetPodStatus()
	if err != nil {
		return fmt.Errorf("failed to get pod status: %w", err)
	}
	// check pod level seccomp profile (might be overridden at container level)
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		watchedContainer.SeccompProfilePath = podSpec.SecurityContext.SeccompProfile.LocalhostProfile
	}
	// fill container infos
	if watchedContainer.ContainerInfos == nil {
		watchedContainer.ContainerInfos = make(map[ContainerType][]ContainerInfo)
	}
	checkContainers := func(containers iter.Seq2[int, v1.Container], containerStatuses []v1.ContainerStatus, containerType ContainerType) error {
		statusesMap := utils.MapContainerStatuses(containerStatuses)
		var containersInfo []ContainerInfo
		for i, c := range containers {
			normalizedImageName := normalizeImageName(c.Image)
			containersInfo = append(containersInfo, ContainerInfo{
				Name:     c.Name,
				ImageTag: normalizedImageName,
				ImageID:  statusesMap[c.Name].ImageID,
			})
			if c.Name == containerName {
				watchedContainer.ContainerIndex = i
				watchedContainer.ContainerType = containerType
				if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
					watchedContainer.SeccompProfilePath = c.SecurityContext.SeccompProfile.LocalhostProfile
				}
				watchedContainer.ImageTag = normalizedImageName
				watchedContainer.ImageID = statusesMap[c.Name].ImageID
			}
		}
		watchedContainer.ContainerInfos[containerType] = containersInfo
		return nil
	}
	// containers
	if err := checkContainers(containersIterator(podSpec.Containers), podStatus.ContainerStatuses, Container); err != nil {
		return err
	}
	// initContainers
	if err := checkContainers(containersIterator(podSpec.InitContainers), podStatus.InitContainerStatuses, InitContainer); err != nil {
		return err
	}
	// ephemeralContainers
	if err := checkContainers(ephemeralContainersIterator(podSpec.EphemeralContainers), podStatus.EphemeralContainerStatuses, EphemeralContainer); err != nil {
		return err
	}
	return nil
}

func containersIterator(c []v1.Container) iter.Seq2[int, v1.Container] {
	return func(yield func(int, v1.Container) bool) {
		for i := 0; i < len(c); i++ {
			if !yield(i, c[i]) {
				return
			}
		}
	}
}

func ephemeralContainersIterator(c []v1.EphemeralContainer) iter.Seq2[int, v1.Container] {
	return func(yield func(int, v1.Container) bool) {
		for i := 0; i < len(c); i++ {
			if !yield(i, v1.Container(c[i].EphemeralContainerCommon)) {
				return
			}
		}
	}
}

func normalizeImageName(image string) string {
	ref, err := name.ParseReference(image)
	if err != nil {
		logger.L().Debug("failed to parse image reference", helpers.Error(err), helpers.String("image", image))
		return image
	}
	// docker.io is parsed as index.docker.io
	return strings.Replace(ref.Name(), "index.docker.io", "docker.io", 1)
}
