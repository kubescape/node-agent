package hosthashsensor

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	sha256simd "github.com/minio/sha256-simd"
	"github.com/panjf2000/ants/v2"
	"istio.io/pkg/cache"
)

const (
	hashCacheTTL                  = 10 * time.Minute
	hashCacheEvictionInterval     = 10 * time.Minute
	hashCacheMaxItems             = 10000
	cooldownCacheTTL              = 5 * time.Minute
	cooldownCacheEvictionInterval = 5 * time.Minute
	cooldownCacheMaxItems         = 10000
)

type Hashes struct {
	md5         string
	sha1        string
	sha256      string
	timeOfCheck time.Time
}

type HashRequest struct {
	md5    bool
	sha1   bool
	sha256 bool
}

type WorkerJob struct {
	eventType utils.EventType
	event     utils.K8sEvent
}

// Helper function to get mount namespace ID from a path
func getHostMountNamespaceId() (uint64, error) {
	mountNsFile, err := os.Open("/proc/1/ns/mnt")
	if err != nil {
		return 0, fmt.Errorf("failed to open mount namespace file: %v", err)
	}
	defer mountNsFile.Close()

	mountNsStat, err := mountNsFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to stat mount namespace file: %v", err)
	}

	return mountNsStat.Sys().(*syscall.Stat_t).Ino, nil
}

func CreateHostHashSensor(cfg config.Config, exporter exporters.Exporter, metrics metricsmanager.MetricsManager) (*HostHashSensorService, error) {
	service := &HostHashSensorService{cfg: &cfg, exporter: &exporter, metricsManager: &metrics}

	// Get host mount namespace ID
	nsId, err := getHostMountNamespaceId()
	if err != nil {
		return nil, fmt.Errorf("failed to get host mount namespace ID: %v", err)
	}
	service.hostMountNamespaceId = nsId

	// Get host root
	service.hostRoot = os.Getenv("HOST_ROOT")

	service.hashWorkerPool, err = ants.NewPoolWithFunc(10, service.processEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash worker pool: %v", err)
	}

	service.sendQueue, err = createSendQueue(exporter)
	if err != nil {
		return nil, fmt.Errorf("failed to create send queue: %v", err)
	}

	service.hashCache = cache.NewLRU(hashCacheTTL, hashCacheEvictionInterval, hashCacheMaxItems)
	service.cooldownCache = cache.NewLRU(cooldownCacheTTL, cooldownCacheEvictionInterval, cooldownCacheMaxItems)

	// Create file filters
	service.fileFilters = []FileFilterInterface{
		&SimpleFileFilter{},
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}
	return service, nil
}

func (s *HostHashSensorService) Start() error {
	// Set up eBPF for getting noticiations on open, close and exec events
	s.sendQueue.Start()
	return nil
}

func (s *HostHashSensorService) Stop() error {
	if s.hashWorkerPool != nil {
		s.hashWorkerPool.Release()
		s.hashWorkerPool = nil
	}
	s.sendQueue.Stop()
	return nil
}

func (s *HostHashSensorService) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	s.hashWorkerPool.Invoke(WorkerJob{
		eventType: eventType,
		event:     event,
	})
}

func (s *HostHashSensorService) processEvent(job interface{}) {
	jobData, ok := job.(WorkerJob)
	if !ok {
		return
	}
	eventType := jobData.eventType
	event := jobData.event

	if eventType != utils.ExecveEventType && eventType != utils.OpenEventType {
		logger.L().Debug("HostHashSensorService.processEvent - received event is not an Execve or Open event", helpers.String("event", fmt.Sprintf("%+v", event)))
		return
	}

	fileToCheck := ""
	accessType := FileAccessTypeOpenRead
	var pid uint32
	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			logger.L().Debug("HostHashSensorService.processEvent - received event is not an ExecEvent", helpers.String("event", fmt.Sprintf("%+v", event)))
			return
		}

		fileToCheck = execEvent.ExePath
		accessType = FileAccessTypeExec
		pid = execEvent.Ppid
	} else if eventType == utils.OpenEventType {
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			logger.L().Debug("HostHashSensorService.processEvent - received event is not an OpenEvent", helpers.String("event", fmt.Sprintf("%+v", event)))
			return
		}
		for _, flag := range openEvent.Flags {
			if flag == "O_RDONLY" {
				accessType = FileAccessTypeOpenRead
				break
			} else if flag == "O_WRONLY" {
				accessType = FileAccessTypeOpenWrite
				break
			} else if flag == "O_RDWR" {
				accessType = FileAccessTypeOpenReadWrite
				break
			}
		}
		fileToCheck = openEvent.FullPath
		pid = openEvent.Pid
	}

	// Check if it is a file that we should check
	if !s.shouldCheckFile(fileToCheck, accessType) {
		//logger.L().Debug("HostHashSensorService.processEvent - file is not a file that we should check", helpers.String("file", fileToCheck))
		return
	}

	// Convert the file path to a path that the agent can use
	convertedFilePath, err := s.convertFilePathToAgentPath(eventType, event, fileToCheck)
	if err != nil {
		logger.L().Debug("HostHashSensorService.processEvent - failed to convert file path to agent path", helpers.String("error", err.Error()))
		return
	}

	var hashes Hashes
	if hashes, ok := s.isFileInCache(convertedFilePath); !ok {
		// Calculate the hash of the file
		hashes, err = s.calculateHash(convertedFilePath, HashRequest{
			md5:    true,
			sha1:   true,
			sha256: true,
		})
		if err != nil {
			logger.L().Debug("HostHashSensorService.processEvent - failed to calculate hash", helpers.String("error", err.Error()))
			return
		}
		s.putFileInCache(convertedFilePath, hashes)
	}

	// Check if the file is in the cooldown cache
	cooldownCacheKey := fmt.Sprintf("%s:%s:%d", convertedFilePath, hashes.md5, pid)
	if _, ok := s.cooldownCache.Get(cooldownCacheKey); ok {
		return
	} else {
		s.cooldownCache.SetWithExpiration(cooldownCacheKey, true, cooldownCacheTTL)
	}

	// Send the alert
	s.putEventOnSendQueue(eventType, event, hashes, fileToCheck, convertedFilePath)
}

func (s *HostHashSensorService) shouldCheckFile(fileToCheck string, accessType FileAccessType) bool {
	for _, filter := range s.fileFilters {
		if filter.ShouldTrack(fileToCheck, accessType) {
			return true
		}
	}
	return false
}

func (s *HostHashSensorService) calculateHash(fileToCheck string, hashRequest HashRequest) (Hashes, error) {
	f, err := os.Open(fileToCheck)
	if err != nil {
		return Hashes{}, err
	}
	defer f.Close()

	h256 := sha256simd.New()
	md5 := md5.New()
	h1 := sha1.New()

	buf := make([]byte, 32*1024) // 32KB buffer for efficient reading

	for {
		n, err := f.Read(buf)
		if n > 0 {
			if hashRequest.sha256 {
				h256.Write(buf[:n])
			}
			if hashRequest.md5 {
				md5.Write(buf[:n])
			}
			if hashRequest.sha1 {
				h1.Write(buf[:n])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Hashes{}, err
		}
	}

	md5Hash := ""
	sha1Hash := ""
	sha256Hash := ""

	if hashRequest.md5 {
		md5Hash = fmt.Sprintf("%x", md5.Sum(nil))
	}

	if hashRequest.sha1 {
		sha1Hash = fmt.Sprintf("%x", h1.Sum(nil))
	}

	if hashRequest.sha256 {
		sha256Hash = fmt.Sprintf("%x", h256.Sum(nil))
	}

	timeOfCheck := time.Now()

	return Hashes{
		md5:         md5Hash,
		sha1:        sha1Hash,
		sha256:      sha256Hash,
		timeOfCheck: timeOfCheck,
	}, nil
}

func (s *HostHashSensorService) convertFilePathToAgentPath(eventType utils.EventType, event utils.K8sEvent, fileToCheck string) (string, error) {
	var eventMountNsId uint64
	var pid uint32

	if !filepath.IsAbs(fileToCheck) {
		return "", fmt.Errorf("file path must be absolute: %s", fileToCheck)
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return "", fmt.Errorf("event is not an ExecEvent")
		}
		eventMountNsId = execEvent.MountNsID
		pid = execEvent.Pid
	} else if eventType == utils.OpenEventType {
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			return "", fmt.Errorf("event is not an OpenEvent")
		}
		eventMountNsId = openEvent.MountNsID
		pid = openEvent.Pid
	}

	rFilePath := fileToCheck
	if eventMountNsId != s.hostMountNamespaceId {
		// Containerized process, we need to get the file from the host
		rFilePath = fmt.Sprintf("/proc/%d/root%s", pid, fileToCheck)

		// TODO: use the pid of the root process of the container to get the file from the host
		// to make sure the path still exists (the process might have been terminated by the time we get the event)
	}

	// Add the host root to the file path
	rFilePath = filepath.Join(s.hostRoot, rFilePath)

	return rFilePath, nil
}

func (s *HostHashSensorService) isFileInCache(fileToCheck string) (Hashes, bool) {
	hashes, ok := s.hashCache.Get(fileToCheck)
	if !ok {
		return Hashes{}, false
	}
	// Get time time of last modification
	info, err := os.Stat(fileToCheck)
	if err != nil {
		return Hashes{}, false
	}
	answerHash, ok := hashes.(Hashes)
	if !ok {
		s.hashCache.Remove(fileToCheck)
		return Hashes{}, false
	}
	if answerHash.timeOfCheck.Before(info.ModTime()) {
		s.hashCache.Remove(fileToCheck)
		return Hashes{}, false
	}
	return answerHash, true
}

func (s *HostHashSensorService) putFileInCache(fileToCheck string, hashes Hashes) {
	s.hashCache.Set(fileToCheck, hashes)
}

func (s *HostHashSensorService) putEventOnSendQueue(eventType utils.EventType, event utils.K8sEvent, hashes Hashes, fileToCheck string, convertedFilePath string) {
	var pid uint32
	var action FileAccessType
	var igEvent *igtypes.Event
	var fileDetails armotypes.File
	var processDetails armotypes.Process
	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			logger.L().Error("Event is not an ExecEvent")
			return
		}
		pid = execEvent.Pid
		action = FileAccessTypeExec
		igEvent = execEvent.GetBaseEvent()
		fileDetails.Ownership.Uid = &execEvent.Uid
		fileDetails.Ownership.Gid = &execEvent.Gid
		processDetails.PID = execEvent.Pid
		processDetails.PPID = execEvent.Ppid
		processDetails.Comm = execEvent.Comm
		processDetails.Path = execEvent.ExePath
		processDetails.Uid = &execEvent.Uid
		processDetails.Gid = &execEvent.Gid
		processDetails.Cwd = execEvent.Cwd
		processDetails.UpperLayer = &execEvent.UpperLayer
		processDetails.Cmdline = strings.Join(execEvent.Args, " ")
	} else if eventType == utils.OpenEventType {
		openEvent, ok := event.(*events.OpenEvent)
		if !ok {
			logger.L().Error("Event is not an OpenEvent")
			return
		}
		pid = openEvent.Pid
		action = FileAccessTypeOpenRead
		for _, flag := range openEvent.Flags {
			if flag == "O_RDONLY" {
				action = FileAccessTypeOpenRead
				break
			} else if flag == "O_WRONLY" {
				action = FileAccessTypeOpenWrite
				break
			} else if flag == "O_RDWR" {
				action = FileAccessTypeOpenReadWrite
				break
			}
		}
		igEvent = openEvent.GetBaseEvent()
		fileDetails.Ownership.Uid = &openEvent.Uid
		fileDetails.Ownership.Gid = &openEvent.Gid
		processDetails.PID = openEvent.Pid
		processDetails.Comm = openEvent.Comm
		processDetails.Uid = &openEvent.Uid
		processDetails.Gid = &openEvent.Gid
	} else {
		logger.L().Error("Event is not an ExecEvent or OpenEvent")
		return
	}

	fileDetails.Path = fileToCheck
	fileDetails.Hashes = armotypes.FileHashes{
		MD5:    hashes.md5,
		SHA1:   hashes.sha1,
		SHA256: hashes.sha256,
	}
	if info, err := os.Stat(convertedFilePath); err == nil {
		fileDetails.Timestamps.ModificationTime = info.ModTime()
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok {
			fileDetails.Timestamps.AccessTime = time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
			fileDetails.Timestamps.CreationTime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		}
		fileDetails.Size = info.Size()
		fileDetails.Attributes.Permissions = fmt.Sprintf("%o", info.Mode())
	}

	// Create the finding
	finding := FileHashResultFinding{
		Hashes:         hashes,
		Timestamp:      time.Unix(0, int64(igEvent.Timestamp)),
		FileDetails:    fileDetails,
		ProcessDetails: processDetails,
		Pid:            int(pid),
		Action:         action,
		Event:          *igEvent,
	}

	s.sendQueue.PutOnSendQueue(finding)

}
