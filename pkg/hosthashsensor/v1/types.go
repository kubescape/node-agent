package hosthashsensor

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hosthashsensor"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/panjf2000/ants/v2"
	"istio.io/pkg/cache"
)

type HostHashSensorServiceInterface interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
	Stop() error
}

type FileAccessType int

const (
	FileAccessTypeOpenRead FileAccessType = iota
	FileAccessTypeOpenWrite
	FileAccessTypeOpenReadWrite
	FileAccessTypeClose
	FileAccessTypeExec
)

type FileFilterInterface interface {
	ShouldTrack(path string, accessType FileAccessType) bool
}

type HostHashSensorService struct {
	cfg                  *config.Config
	exporter             *exporters.Exporter
	metricsManager       *metricsmanager.MetricsManager
	hostMountNamespaceId uint64
	hostRoot             string
	fileFilters          []FileFilterInterface
	hashWorkerPool       *ants.PoolWithFunc
	sendQueue            *SendQueue
	hashCache            cache.ExpiringCache
	cooldownCache        cache.ExpiringCache
}

type SendQueue struct {
	started  bool
	queue    chan hosthashsensor.FileHashResult
	exporter exporters.Exporter
}

type FileHashResultFinding struct {
	Hashes         Hashes
	FileDetails    apitypes.File
	ProcessDetails apitypes.Process
	Timestamp      time.Time
	Pid            int
	Action         FileAccessType
	Event          igtypes.Event
}
