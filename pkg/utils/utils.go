package utils

import (
	"errors"
	"math/rand"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/goradd/maps"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandler2 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	ContainerHasTerminatedError = errors.New("container has terminated")
	IncompleteSBOMError         = errors.New("incomplete SBOM")
)

type PackageSourceInfoData struct {
	Exist                 bool
	PackageSPDXIdentifier []v1beta1.ElementID
}

type ContainerType int

const (
	Unknown = iota
	Container
	InitContainer
	EphemeralContainer
)

type WatchedContainerData struct {
	InstanceID                               instanceidhandler.IInstanceID
	UpdateDataTicker                         *time.Ticker
	SyncChannel                              chan error
	FilteredSpdxData                         *v1beta1.SBOMSyftFiltered
	RelevantRealtimeFilesBySPDXIdentifier    map[v1beta1.ElementID]bool
	RelevantRealtimeFilesByPackageSourceInfo map[string]*PackageSourceInfoData
	RelevantSyftFilesByIdentifier            map[string]bool
	ParentResourceVersion                    string
	ContainerID                              string
	ImageTag                                 string
	ImageID                                  string
	Wlid                                     string
	TemplateHash                             string
	K8sContainerID                           string
	SBOMResourceVersion                      int
	ContainerType                            ContainerType
	ContainerIndex                           int
	NsMntId                                  uint64
	InitialDelayExpired                      bool
}

func Between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	substr := value[posFirst+len(a):]
	posLast := strings.Index(substr, b) + posFirst + len(a)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

func After(value string, a string) string {
	// Get substring after a string.
	pos := strings.LastIndex(value, a)
	if pos == -1 {
		return ""
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return ""
	}
	return value[adjustedPos:]
}

func CurrentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}

func CreateK8sContainerID(namespaceName string, podName string, containerName string) string {
	return strings.Join([]string{namespaceName, podName, containerName}, "/")
}

// AddRandomDuration adds between min and max seconds to duration
func AddRandomDuration(min, max int, duration time.Duration) time.Duration {
	// we don't initialize the seed, so we will get the same sequence of random numbers every time
	randomDuration := time.Duration(rand.Intn(max+1-min)+min) * time.Second
	return randomDuration + duration
}

func Atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func GetLabels(watchedContainer *WatchedContainerData, stripContainer bool) map[string]string {
	labels := watchedContainer.InstanceID.GetLabels()
	for i := range labels {
		if labels[i] == "" {
			delete(labels, i)
		} else if stripContainer && i == instanceidhandler2.ContainerNameMetadataKey {
			delete(labels, i)
		} else {
			if i == instanceidhandler2.KindMetadataKey {
				labels[i] = wlid.GetKindFromWlid(watchedContainer.Wlid)
			} else if i == instanceidhandler2.NameMetadataKey {
				labels[i] = wlid.GetNameFromWlid(watchedContainer.Wlid)
			}
			errs := validation.IsValidLabelValue(labels[i])
			if len(errs) != 0 {
				logger.L().Debug("label is not valid", helpers.String("label", labels[i]))
				for j := range errs {
					logger.L().Debug("label err description", helpers.String("Err: ", errs[j]))
				}
				delete(labels, i)
			}
		}
	}
	if watchedContainer.ParentResourceVersion != "" {
		labels[instanceidhandler2.ResourceVersionMetadataKey] = watchedContainer.ParentResourceVersion
	}
	if watchedContainer.TemplateHash != "" {
		labels[instanceidhandler2.TemplateHashKey] = watchedContainer.TemplateHash
	}
	return labels
}

func GetApplicationProfileContainer(profile *v1beta1.ApplicationProfile, containerType ContainerType, containerIndex int) *v1beta1.ApplicationProfileContainer {
	if profile == nil {
		return nil
	}
	switch containerType {
	case Container:
		if len(profile.Spec.Containers) > containerIndex {
			return &profile.Spec.Containers[containerIndex]
		}
	case InitContainer:
		if len(profile.Spec.InitContainers) > containerIndex {
			return &profile.Spec.InitContainers[containerIndex]
		}
	}
	return nil
}

func InsertApplicationProfileContainer(profile *v1beta1.ApplicationProfile, containerType ContainerType, containerIndex int, profileContainer *v1beta1.ApplicationProfileContainer) {
	switch containerType {
	case Container:
		if len(profile.Spec.Containers) <= containerIndex {
			profile.Spec.Containers = append(profile.Spec.Containers, make([]v1beta1.ApplicationProfileContainer, containerIndex-len(profile.Spec.Containers)+1)...)
		}
		profile.Spec.Containers[containerIndex] = *profileContainer
	case InitContainer:
		if len(profile.Spec.InitContainers) <= containerIndex {
			profile.Spec.InitContainers = append(profile.Spec.InitContainers, make([]v1beta1.ApplicationProfileContainer, containerIndex-len(profile.Spec.InitContainers)+1)...)
		}
		profile.Spec.InitContainers[containerIndex] = *profileContainer
	}
}

// WaitGetSafeMap waits for a value to be loaded into a SafeMap, with a timeout of 1 minute
func WaitGetSafeMap[K comparable, V any](m *maps.SafeMap[K, V], k K) (V, error) {
	var tries int
	for {
		v, ok := m.Load(k)
		if ok {
			return v, nil
		}
		if tries > 60 {
			return v, errors.New("timeout")
		}
		time.Sleep(1 * time.Second)
		tries++
	}
}
