package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/goradd/maps"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/prometheus/procfs"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	ContainerHasTerminatedError = errors.New("container has terminated")
	ContainerReachedMaxTime     = errors.New("container reached max time")
	ObjectCompleted             = errors.New("object is completed")
	TooLargeObjectError         = errors.New("object is too large")
)

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
	WatchedContainerStatusReady        WatchedContainerStatus = helpersv1.Learning
	WatchedContainerStatusCompleted    WatchedContainerStatus = helpersv1.Completed

	WatchedContainerStatusMissingRuntime WatchedContainerStatus = helpersv1.MissingRuntime
	WatchedContainerStatusTooLarge       WatchedContainerStatus = helpersv1.TooLarge
)

type WatchedContainerCompletionStatus string

const (
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
	PreviousProfileTS                          *time.Time
	Uuid                                       string
}

type ContainerInfo struct {
	Name     string
	ImageTag string
	ImageID  string
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

func CreateK8sContainerID(namespaceName string, podName string, containerId string) string {
	return strings.Join([]string{namespaceName, podName, containerId}, "/")
}

func CreateK8sPodID(namespaceName string, podName string) string {
	return strings.Join([]string{namespaceName, podName}, "/")
}

// AddJitter adds jitter percent to the duration
func AddJitter(duration time.Duration, maxJitterPercentage int) time.Duration {
	if maxJitterPercentage == 0 {
		return duration
	}
	jitter := 1 + rand.Intn(maxJitterPercentage)/100
	return duration * time.Duration(jitter)
}

// Jitter returns a random duration
func Jitter(duration *time.Duration, maxJitterPercentage float64) {
	if *duration == 0 {
		return
	}

	jitterFraction := maxJitterPercentage / 100.0
	jitterDuration := time.Duration(float64(*duration) * jitterFraction * (rand.Float64()*2 - 1))
	*duration += jitterDuration
}

// RandomDuration returns a duration between 1/2 max and max
func RandomDuration(max int, duration time.Duration) time.Duration {
	// we don't initialize the seed, so we will get the same sequence of random numbers every time
	mini := max / 2
	return time.Duration(rand.Intn(1+max-mini)+mini) * duration
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
	labels[helpersv1.ContainerTypeMetadataKey] = watchedContainer.ContainerType.String()
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
		statusesMap := MapContainerStatuses(containerStatuses)
		var containersInfo []ContainerInfo
		for i, c := range containers {
			normalizedImageName := NormalizeImageName(c.Image)
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

func NormalizeImageName(image string) string {
	ref, err := name.ParseReference(image)
	if err != nil {
		logger.L().Debug("failed to parse image reference", helpers.Error(err), helpers.String("image", image))
		return image
	}
	// docker.io is parsed as index.docker.io
	return strings.Replace(ref.Name(), "index.docker.io", "docker.io", 1)
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
		existingPatch = append(existingPatch,
			PatchOperation{
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

func GetProcessEnv(pid int) (map[string]string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	env, err := proc.Environ()
	if err != nil {
		return nil, err
	}

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	return envMap, nil
}

// Get the path of the file on the node.
func GetHostFilePathFromEvent(event K8sEvent, containerPid uint32) (string, error) {
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
		if event.Args[0] != "" {
			return event.Args[0]
		}
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

func CalculateSHA256FileExecHash(path string, args []string) string {
	hsh := sha256.New()
	hsh.Write([]byte(fmt.Sprintf("%s;%v", path, args)))
	hashInBytes := hsh.Sum(nil)
	return hex.EncodeToString(hashInBytes)
}

func CalculateSHA256FileOpenHash(path string) string {
	hsh := sha256.New()
	hsh.Write([]byte(path))
	hashInBytes := hsh.Sum(nil)
	return hex.EncodeToString(hashInBytes)
}

// CalculateFileHashes calculates both SHA1 and MD5 hashes of the given file.
func CalculateFileHashes(path string) (sha1Hash string, md5Hash string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	sha1Hash256 := sha1.New()
	md5Hash256 := md5.New()

	multiWriter := io.MultiWriter(sha1Hash256, md5Hash256)

	if _, err := io.Copy(multiWriter, file); err != nil {
		return "", "", err
	}

	sha1HashString := hashToString(sha1Hash256)
	md5HashString := hashToString(md5Hash256)

	return sha1HashString, md5HashString, nil
}

// hashToString converts a hash.Hash to a hexadecimal string.
func hashToString(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

// Creates a process tree from a process.
// The process tree will be built from scanning the /proc filesystem.
func CreateProcessTree(process *apitypes.Process, shimPid uint32) (apitypes.Process, error) {
	pfs, err := procfs.NewFS("/proc")
	if err != nil {
		return apitypes.Process{}, err
	}

	proc, err := pfs.Proc(int(process.PID))
	if err != nil {
		logger.L().Debug("Failed to get process", helpers.String("error", err.Error()))
		return apitypes.Process{}, err
	}

	// build the process tree
	treeRoot, err := buildProcessTree(proc, &pfs, shimPid, nil)
	if err != nil {
		return apitypes.Process{}, err
	}

	return treeRoot, nil
}

// Recursively build the process tree.
func buildProcessTree(proc procfs.Proc, procfs *procfs.FS, shimPid uint32, processTree *apitypes.Process) (apitypes.Process, error) {
	// If the current process is the shim, return the process tree.
	if proc.PID == int(shimPid) {
		return *processTree.DeepCopy(), nil
	}

	stat, err := proc.Stat()
	if err != nil {
		return apitypes.Process{}, err
	}

	parent, err := procfs.Proc(stat.PPID)
	if err != nil {
		return apitypes.Process{}, err
	}

	var uid, gid uint32
	status, err := proc.NewStatus()
	if err != nil {
		return apitypes.Process{}, err
	} else {
		uid = uint32(status.UIDs[1])
		gid = uint32(status.GIDs[1])
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
		if currentProcess.ChildrenMap == nil {
			currentProcess.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		currentProcess.ChildrenMap[apitypes.CommPID{Comm: processTree.Comm, PID: processTree.PID}] = processTree
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

	for i := range process.ChildrenMap {
		if p := GetProcessFromProcessTree(process.ChildrenMap[i], pid); p != nil {
			return p
		}
	}

	return nil
}

// TrimRuntimePrefix removes the runtime prefix from a container ID.
func TrimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

func GetContainerStatuses(podStatus v1.PodStatus) []v1.ContainerStatus {
	return slices.Concat(podStatus.ContainerStatuses, podStatus.InitContainerStatuses, podStatus.EphemeralContainerStatuses)
}

func ChunkBy[T any](items []T, chunkSize int) [][]T {
	var chunks [][]T
	if chunkSize > 0 {
		for chunkSize < len(items) {
			items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
		}
	}
	return append(chunks, items)
}

func DiskUsage(path string) int64 {
	var s int64
	dir, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return s
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println(err)
		return s
	}

	for _, f := range files {
		if f.IsDir() {
			s += DiskUsage(filepath.Join(path, f.Name()))
		} else {
			s += f.Size()
		}
	}
	return s
}

func IsSensitivePath(fullPath string, paths []string) bool {
	if fullPath == "" {
		return false
	}

	// Clean and normalize the input path once
	fullPath = filepath.Clean(fullPath)
	if !filepath.IsAbs(fullPath) {
		fullPath = filepath.Clean("/" + fullPath)
	}

	// Pre-compute the directory of the full path since it's used in prefix checks
	fullPathDir := filepath.Dir(fullPath)

	for _, sensitivePath := range paths {
		if sensitivePath == "" {
			continue
		}

		// Clean and normalize the sensitive path
		sensitivePath = filepath.Clean(sensitivePath)
		if !filepath.IsAbs(sensitivePath) {
			sensitivePath = filepath.Clean("/" + sensitivePath)
		}

		// Check exact match first (fast path)
		if fullPath == sensitivePath {
			return true
		}

		// Check if the path is within the sensitive directory
		// Note: This assumes sensitivePath is already verified as a directory
		// through external means if needed
		if strings.HasPrefix(fullPathDir, sensitivePath) {
			return true
		}
	}
	return false
}

func MapContainerStatuses(statuses []v1.ContainerStatus) map[string]v1.ContainerStatus {
	statusesMap := make(map[string]v1.ContainerStatus)
	for _, s := range statuses {
		statusesMap[s.Name] = s
	}
	return statusesMap
}

type WorkloadKind string

const (
	Deployment  WorkloadKind = "Deployment"
	StatefulSet WorkloadKind = "StatefulSet"
	DaemonSet   WorkloadKind = "DaemonSet"
	CronJob     WorkloadKind = "CronJob"
	ReplicaSet  WorkloadKind = "ReplicaSet"
)

func ExtractWorkloadName(podName string, kind WorkloadKind) string {
	if podName == "" {
		return ""
	}

	parts := strings.Split(podName, "-")
	if len(parts) == 1 {
		return podName
	}

	switch kind {
	case Deployment:
		// Remove last two parts (hash and random string)
		// e.g., nginx-7869c5f687-xy123 -> nginx
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-2], "-")
		}

	case StatefulSet:
		// Remove the last part (ordinal number)
		// e.g., mysql-0 -> mysql
		return strings.Join(parts[:len(parts)-1], "-")

	case DaemonSet:
		// Remove the last part (random string)
		// e.g., fluentd-78k9x -> fluentd
		return strings.Join(parts[:len(parts)-1], "-")

	case CronJob:
		// Remove last two parts (job hash and random string)
		// e.g., backup-cron-1234567890-abcde -> backup-cron
		if len(parts) >= 3 {
			return strings.Join(parts[:len(parts)-2], "-")
		}
	}

	return podName
}

func FuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
