package utils

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type BaseEvent struct {
	IDataEvent
	Comm                 string
	Container            string
	ContainerID          string
	ContainerImage       string
	ContainerImageDigest string
	Error                *int64
	EventType            EventType
	Extra                any
	Gid                  *uint32
	HostNetwork          *bool
	Namespace            string
	PID                  *uint32
	Pcomm                string
	Pod                  string
	PodLabels            map[string]string
	Ppid                 *uint32
	Timestamp            *types.Time
	Uid                  *uint32
}

var _ EnrichEvent = (*BaseEvent)(nil)

func (e *BaseEvent) GetComm() string {
	if e.Comm == "" {
		switch e.EventType {
		case SyscallEventType:
			// FIXME this is a temporary workaround until the gadget has proc enrichment
			e.Comm = e.GetContainer()
		default:
			val, err := e.GetDatasource().GetField("proc.comm").String(e.GetData())
			if err != nil {
				logger.L().Warning("GetComm - proc.comm field not found or invalid", helpers.String("eventType", string(e.EventType)))
				return ""
			}
			e.Comm = val
		}
	}
	return e.Comm
}

func (e *BaseEvent) GetContainer() string {
	if e.Container == "" {
		val, err := e.GetDatasource().GetField("k8s.containerName").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetContainer - k8s.containerName field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Container = val
	}
	return e.Container
}

func (e *BaseEvent) GetContainerID() string {
	if e.ContainerID == "" {
		val, err := e.GetDatasource().GetField("runtime.containerId").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetContainerID - runtime.containerId field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.ContainerID = val
	}
	return e.ContainerID
}

func (e *BaseEvent) GetContainerImage() string {
	if e.ContainerImage == "" {
		val, err := e.GetDatasource().GetField("runtime.containerImageName").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetContainerImage - runtime.containerImageName field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.ContainerImage = val
	}
	return e.ContainerImage
}

func (e *BaseEvent) GetContainerImageDigest() string {
	if e.ContainerImageDigest == "" {
		val, err := e.GetDatasource().GetField("runtime.containerImageDigest").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetContainerImageDigest - runtime.containerImageDigest field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.ContainerImageDigest = val
	}
	return e.ContainerImageDigest
}

func (e *BaseEvent) GetError() int64 {
	if e.Error == nil {
		val, err := e.GetDatasource().GetField("error_raw").Int64(e.GetData())
		if err != nil {
			logger.L().Warning("GetError - error_raw field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		e.Error = &val
	}
	return *e.Error
}

func (e *BaseEvent) GetEventType() EventType {
	return e.EventType
}

func (e *BaseEvent) GetExtra() any {
	return e.Extra
}

func (e *BaseEvent) GetGid() *uint32 {
	if e.Gid == nil {
		gid, err := e.GetDatasource().GetField("proc.creds.gid").Uint32(e.GetData())
		if err != nil {
			logger.L().Warning("GetGid - proc.creds.gid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return nil
		}
		e.Gid = &gid
	}
	return e.Gid
}

func (e *BaseEvent) GetHostNetwork() bool {
	if e.HostNetwork == nil {
		val, err := e.GetDatasource().GetField("k8s.hostnetwork").Bool(e.GetData())
		if err != nil {
			logger.L().Warning("GetHostNetwork - k8s.hostnetwork field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return false
		}
		e.HostNetwork = &val
	}
	return *e.HostNetwork
}

func (e *BaseEvent) GetNamespace() string {
	if e.Namespace == "" {
		val, err := e.GetDatasource().GetField("k8s.namespace").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetNamespace - k8s.namespace field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Namespace = val
	}
	return e.Namespace
}

func (e *BaseEvent) GetPcomm() string {
	if e.Pcomm == "" {
		val, err := e.GetDatasource().GetField("proc.parent.comm").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetPcomm - proc.parent.comm field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Pcomm = val
	}
	return e.Pcomm
}

func (e *BaseEvent) GetPID() uint32 {
	if e.PID == nil {
		val, err := e.GetDatasource().GetField("proc.pid").Uint32(e.GetData())
		if err != nil {
			logger.L().Warning("GetPID - proc.pid field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		e.PID = &val
	}
	return *e.PID
}

func (e *BaseEvent) GetPod() string {
	if e.Pod == "" {
		val, err := e.GetDatasource().GetField("k8s.podName").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetPod - k8s.podName field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		e.Pod = val
	}
	return e.Pod
}

func (e *BaseEvent) GetPodLabels() map[string]string {
	if e.PodLabels == nil {
		val, err := e.GetDatasource().GetField("k8s.podLabels").String(e.GetData())
		if err != nil {
			logger.L().Warning("GetPodLabels - k8s.podLabels field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return nil
		}
		e.PodLabels = parseStringToMap(val)
	}
	return e.PodLabels
}

func (e *BaseEvent) GetPpid() uint32 {
	if e.Ppid == nil {
		val, err := e.GetDatasource().GetField("proc.parent.pid").Uint32(e.GetData())
		if err != nil {
			logger.L().Warning("GetPpid - proc.parent.pid field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		e.Ppid = &val
	}
	return *e.Ppid
}

func (e *BaseEvent) GetTimestamp() types.Time {
	if e.Timestamp == nil {
		val, err := e.GetDatasource().GetField("timestamp").Int64(e.GetData())
		if err != nil {
			logger.L().Warning("GetTimestamp - timestamp field not found or invalid", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		t := types.Time(val)
		e.Timestamp = &t
	}
	return *e.Timestamp
}

func (e *BaseEvent) GetUid() *uint32 {
	if e.Uid == nil {
		uid, err := e.GetDatasource().GetField("proc.creds.uid").Uint32(e.GetData())
		if err != nil {
			logger.L().Warning("GetUid - proc.creds.uid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return nil
		}
		e.Uid = &uid
	}
	return e.Uid
}

func (e *BaseEvent) SetExtra(extra any) {
	e.Extra = extra
}
