package utils

import (
	"math/rand"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type PackageSourceInfoData struct {
	Exist                 bool
	PackageSPDXIdentifier []v1beta1.ElementID
}

type WatchedContainerData struct {
	ContainerID                              string
	FilteredSpdxData                         *v1beta1.SBOMSPDXv2p3Filtered
	FirstReport                              bool
	ImageID                                  string
	ImageTag                                 string
	InitialDelayExpired                      bool
	InstanceID                               instanceidhandler.IInstanceID
	K8sContainerID                           string
	NewRelevantData                          bool
	RelevantRealtimeFilesByPackageSourceInfo map[string]*PackageSourceInfoData
	RelevantRealtimeFilesBySPDXIdentifier    map[v1beta1.ElementID]bool
	SBOMResourceVersion                      int
	SyncChannel                              chan error
	UpdateDataTicker                         *time.Ticker
	Wlid                                     string
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

// RandomSleep sleeps between min and max seconds
func RandomSleep(min, max int) {
	// we don't initialize the seed, so we will get the same sequence of random numbers every time
	randomDuration := time.Duration(rand.Intn(max+1-min)+min) * time.Second
	time.Sleep(randomDuration)
}

func Atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}
