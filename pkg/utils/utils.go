package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"node-agent/pkg/objectcache"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/ephemeralcontainerinstance"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/initcontainerinstance"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/prometheus/procfs"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

var (
	ContainerHasTerminatedError = errors.New("container has terminated")
	ContainerReachedMaxTime     = errors.New("container reached max time")
	TooLargeObjectError         = errors.New("object is too large")
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

type WatchedContainerStatus string

const (
	WatchedContainerStatusInitializing WatchedContainerStatus = helpersv1.Initializing
	WatchedContainerStatusReady        WatchedContainerStatus = helpersv1.Ready
	WatchedContainerStatusCompleted    WatchedContainerStatus = helpersv1.Completed

	WatchedContainerStatusMissingRuntime WatchedContainerStatus = helpersv1.MissingRuntime
	WatchedContainerStatusTooLarge       WatchedContainerStatus = helpersv1.TooLarge
)

type WatchedContainerCompletionStatus string

const (
	WatchedContainerCompletionStatusPartial WatchedContainerCompletionStatus = helpersv1.Partial
	WatchedContainerCompletionStatusFull    WatchedContainerCompletionStatus = helpersv1.Complete
)

func (c ContainerType) String() string {
	return [...]string{"unknown", "containers", "initContainers", "ephemeralContainers"}[c]
}

type WatchedContainerData struct {
	InstanceID                                 instanceidhandler.IInstanceID
	UpdateDataTicker                           *time.Ticker
	SyncChannel                                chan error
	SBOMSyftFiltered                           *v1beta1.SBOMSyftFiltered
	RelevantRealtimeFilesByIdentifier          map[string]bool
	RelevantRelationshipsArtifactsByIdentifier map[string]bool
	RelevantArtifactsFilesByIdentifier         map[string]bool
	ParentResourceVersion                      string
	ContainerID                                string
	ImageTag                                   string
	ImageID                                    string
	Wlid                                       string
	TemplateHash                               string
	K8sContainerID                             string
	SBOMResourceVersion                        int
	ContainerType                              ContainerType
	ContainerIndex                             int
	ContainerNames                             map[ContainerType][]string
	NsMntId                                    uint64
	InitialDelayExpired                        bool
	statusUpdated                              bool
	status                                     WatchedContainerStatus
	completionStatus                           WatchedContainerCompletionStatus
	ParentWorkloadSelector                     *metav1.LabelSelector
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
				logger.L().Debug("label is not valid", helpers.String("label", labels[i]))
				for j := range errs {
					logger.L().Debug("label err description", helpers.String("Err: ", errs[j]))
				}
				delete(labels, i)
			}
		}
	}
	if watchedContainer.ParentResourceVersion != "" {
		labels[helpersv1.ResourceVersionMetadataKey] = watchedContainer.ParentResourceVersion
	}
	if watchedContainer.TemplateHash != "" {
		labels[helpersv1.TemplateHashKey] = watchedContainer.TemplateHash
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

func (watchedContainer *WatchedContainerData) SetContainerInfo(wl workloadinterface.IWorkload, containerName string) {
	if watchedContainer.ContainerNames == nil {
		watchedContainer.ContainerNames = make(map[ContainerType][]string)
	}
	checkContainers := func(containers []v1.Container, ephemeralContainers []v1.EphemeralContainer, containerType ContainerType) {
		var containerNames []string
		if containerType == EphemeralContainer {
			for i, c := range ephemeralContainers {
				containerNames = append(containerNames, c.Name)
				if c.Name == containerName {
					watchedContainer.ContainerIndex = i
					watchedContainer.ContainerType = containerType
				}
			}
		} else {
			for i, c := range containers {
				containerNames = append(containerNames, c.Name)
				if c.Name == containerName {
					watchedContainer.ContainerIndex = i
					watchedContainer.ContainerType = containerType
				}
			}
		}
		watchedContainer.ContainerNames[containerType] = containerNames
	}
	// containers
	containers, err := wl.GetContainers()
	if err != nil {
		return
	}
	checkContainers(containers, nil, Container)
	// initContainers
	initContainers, err := wl.GetInitContainers()
	if err != nil {
		return
	}
	checkContainers(initContainers, nil, InitContainer)
	// ephemeralContainers
	ephemeralContainers, err := wl.GetEphemeralContainers()
	if err != nil {
		return
	}
	checkContainers(nil, ephemeralContainers, EphemeralContainer)
}

// SetTerminationStatus updates the terminated flag and sets the exit code on the watched container
func (watchedContainer *WatchedContainerData) GetTerminationExitCode(k8sObjectsCache objectcache.K8sObjectCache, namespace, podName, containerName string) int32 {
	time.Sleep(3 * time.Second)
	podStatus := k8sObjectsCache.GetPodStatus(namespace, podName)
	if podStatus != nil {
		for i := range podStatus.ContainerStatuses {
			if podStatus.ContainerStatuses[i].Name == containerName {
				if podStatus.ContainerStatuses[i].LastTerminationState.Terminated != nil {
					return podStatus.ContainerStatuses[i].LastTerminationState.Terminated.ExitCode

				}
			}
		}

		// in case the terminated container is an init or ephemeral container
		// return -1 to avoid setting the status later to completed
		for i := range podStatus.InitContainerStatuses {
			if podStatus.InitContainerStatuses[i].Name == containerName {
				return -1
			}
		}

		for i := range podStatus.EphemeralContainerStatuses {
			if podStatus.EphemeralContainerStatuses[i].Name == containerName {
				return -1
			}
		}
	}

	return 0
}

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// EscapeJSONPointerElement escapes a JSON pointer element
// See https://www.rfc-editor.org/rfc/rfc6901#section-3
func EscapeJSONPointerElement(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func AppendStatusAnnotationPatchOperations(existingPatch []PatchOperation, watchedContainer *WatchedContainerData) []PatchOperation {
	if watchedContainer.statusUpdated {
		existingPatch = append(existingPatch, PatchOperation{
			Op:    "replace",
			Path:  "/metadata/annotations/" + EscapeJSONPointerElement(helpersv1.StatusMetadataKey),
			Value: string(watchedContainer.status),
		},
			PatchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + EscapeJSONPointerElement(helpersv1.CompletionMetadataKey),
				Value: string(watchedContainer.completionStatus),
			},
		)
	}

	return existingPatch
}

func SetInMap(newExecMap *maps.SafeMap[string, mapset.Set[string]]) func(k string, v mapset.Set[string]) bool {
	return func(k string, v mapset.Set[string]) bool {
		if newExecMap.Has(k) {
			newExecMap.Get(k).Append(v.ToSlice()...)
		} else {
			newExecMap.Set(k, v)
		}
		return true
	}
}

func ToInstanceType(c ContainerType) helpersv1.InstanceType {
	switch c {
	case Container:
		return containerinstance.InstanceType
	case InitContainer:
		return initcontainerinstance.InstanceType
	case EphemeralContainer:
		return ephemeralcontainerinstance.InstanceType
	}

	return containerinstance.InstanceType
}

func GetCmdlineByPid(pid int) (*string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	cmdline, err := proc.CmdLine()
	if err != nil {
		return nil, err
	}

	cmdlineStr := strings.Join(cmdline, " ")

	return &cmdlineStr, nil
}

func GetProcessStat(pid int) (*procfs.ProcStat, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	stat, err := proc.Stat()
	if err != nil {
		return nil, err
	}

	return &stat, nil
}

// Get the path of the file on the node.
func GetHostFilePathFromEvent(event interface{}, containerPid uint32) (string, error) {
	if execEvent, ok := event.(*tracerexectype.Event); ok {
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(execEvent)))
		return realPath, nil
	}

	if openEvent, ok := event.(*traceropentype.Event); ok {
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, openEvent.FullPath))
		return realPath, nil
	}

	return "", fmt.Errorf("event is not of type tracerexectype.Event or traceropentype.Event")
}

// Get the path of the executable from the given event.
func GetExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		return event.Args[0]
	}
	return event.Comm
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event *tracerexectype.Event) []string {
	if len(event.Args) > 1 {
		return event.Args[1:]
	}
	return []string{}
}

// Get the size of the given file.
func GetFileSize(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	// Get the file size.
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}

// Calculate the SHA256 hash of the given file.
func CalculateSHA256FileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	return hashString, nil
}

// Calculate the SHA1 hash of the given file.
func CalculateSHA1FileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	return hashString, nil
}

// Calculate the MD5 hash of the given file.
func CalculateMD5FileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	return hashString, nil
}

// Creates a process tree from a process.
// The process tree will be built from scanning the /proc filesystem.
func CreateProcessTree(process *apitypes.Process, shimPid uint32) (*apitypes.Process, error) {
	procfs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := procfs.Proc(int(process.PID))
	if err != nil {
		logger.L().Debug("Failed to get process", helpers.String("error", err.Error()))
		return nil, err
	}

	// build the process tree
	treeRoot, err := buildProcessTree(proc, &procfs, shimPid, nil)
	if err != nil {
		return nil, err
	}

	return treeRoot, nil
}

// Recursively build the process tree.
func buildProcessTree(proc procfs.Proc, procfs *procfs.FS, shimPid uint32, processTree *apitypes.Process) (*apitypes.Process, error) {
	// If the current process is the shim, return the process tree.
	if proc.PID == int(shimPid) {
		return processTree, nil
	}

	stat, err := proc.Stat()
	if err != nil {
		return nil, err
	}

	parent, err := procfs.Proc(stat.PPID)
	if err != nil {
		return nil, err
	}

	var uid, gid uint32
	status, err := proc.NewStatus()
	if err != nil {
		return nil, err
	} else {
		// TODO: When (https://github.com/prometheus/procfs/pull/620) is merged, use the UID and GID as integers.
		uid64, err := strconv.ParseUint(status.UIDs[1], 10, 32)
		if err != nil {
			return nil, err
		}
		uid = uint32(uid64)

		gid64, err := strconv.ParseUint(status.GIDs[1], 10, 32)
		if err != nil {
			return nil, err
		}
		gid = uint32(gid64)
	}

	// Make the parent process the parent of the current process (move the current process to the parent's children).
	currentProcess := apitypes.Process{
		Comm: stat.Comm,
		Path: func() string {
			path, err := proc.Executable()
			if err != nil {
				return ""
			}
			return path
		}(),
		// TODO: Hardlink
		// TODO: UpperLayer
		PID:  uint32(stat.PID),
		PPID: uint32(parent.PID),
		Cmdline: func() string {
			cmdline, err := proc.CmdLine()
			if err != nil {
				return ""
			}
			return strings.Join(cmdline, " ")
		}(),
		Pcomm: func() string {
			pcomm, err := parent.Comm()
			if err != nil {
				return ""
			}
			return pcomm
		}(),
		Gid: &gid,
		Uid: &uid,
		Cwd: func() string {
			cwd, err := proc.Cwd()
			if err != nil {
				return ""
			}
			return cwd
		}(),
	}

	if processTree != nil {
		currentProcess.Children = append(currentProcess.Children, *processTree)

	}
	return buildProcessTree(parent, procfs, shimPid, &currentProcess)
}

func GetPathFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	path, err := proc.Executable()
	if err != nil {
		return "", err
	}

	return path, nil
}

func GetCommFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	comm, err := proc.Comm()
	if err != nil {
		return "", err
	}

	return comm, nil
}

func GetProcessFromProcessTree(process *apitypes.Process, pid uint32) *apitypes.Process {
	if process.PID == pid {
		return process
	}

	for i := range process.Children {
		if p := GetProcessFromProcessTree(&process.Children[i], pid); p != nil {
			return p
		}
	}

	return nil
}
