package adapters

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	iouringsyscall "github.com/iceber/iouring-go/syscall"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

type IoUringAdapter struct {
}

func NewIoUringAdapter() *IoUringAdapter {
	return &IoUringAdapter{}
}

func (c *IoUringAdapter) SetFailureMetadata(failure types.RuleFailure, enrichedEvent *events.EnrichedEvent, _ map[string]any) {
	iouringEvent, ok := enrichedEvent.Event.(utils.IOUring)
	if !ok {
		return
	}

	opcode := iouringEvent.GetOpcode()
	ok, name := GetOpcodeName(uint8(opcode))
	if !ok {
		return
	}

	pid := iouringEvent.GetPID()
	comm := iouringEvent.GetComm()
	baseRuntimeAlert := failure.GetBaseRuntimeAlert()
	baseRuntimeAlert.InfectedPID = pid
	if baseRuntimeAlert.Arguments == nil {
		baseRuntimeAlert.Arguments = make(map[string]interface{})
	}
	baseRuntimeAlert.Arguments["opcode"] = opcode
	baseRuntimeAlert.Arguments["flags"] = iouringEvent.GetFlags()
	baseRuntimeAlert.Arguments["operation"] = name
	baseRuntimeAlert.Identifiers = &common.Identifiers{
		Process: &common.ProcessEntity{
			Name: comm,
		},
	}
	failure.SetBaseRuntimeAlert(baseRuntimeAlert)

	runtimeProcessDetails := apitypes.ProcessTree{
		ProcessTree: apitypes.Process{
			Comm: comm,
			PID:  pid,
			Uid:  iouringEvent.GetUid(),
			Gid:  iouringEvent.GetGid(),
		},
		ContainerID: iouringEvent.GetContainerID(),
	}
	failure.SetRuntimeProcessDetails(runtimeProcessDetails)

	failure.SetTriggerEvent(iouringEvent)

	runtimeAlertK8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:   iouringEvent.GetPod(),
		PodLabels: iouringEvent.GetPodLabels(),
	}
	failure.SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails)
}

var OpcodeMap = map[uint8]string{
	iouringsyscall.IORING_OP_NOP:             "No operation",
	iouringsyscall.IORING_OP_READV:           "Vector read",
	iouringsyscall.IORING_OP_WRITEV:          "Vector write",
	iouringsyscall.IORING_OP_FSYNC:           "File sync",
	iouringsyscall.IORING_OP_READ_FIXED:      "Read with fixed buffers",
	iouringsyscall.IORING_OP_WRITE_FIXED:     "Write with fixed buffers",
	iouringsyscall.IORING_OP_POLL_ADD:        "Add poll request",
	iouringsyscall.IORING_OP_POLL_REMOVE:     "Remove poll request",
	iouringsyscall.IORING_OP_SYNC_FILE_RANGE: "Sync file range",
	iouringsyscall.IORING_OP_SENDMSG:         "Send message",
	iouringsyscall.IORING_OP_RECVMSG:         "Receive message",
	iouringsyscall.IORING_OP_TIMEOUT:         "Timeout operation",
	iouringsyscall.IORING_OP_TIMEOUT_REMOVE:  "Remove timeout",
	iouringsyscall.IORING_OP_ACCEPT:          "Accept connection",
	iouringsyscall.IORING_OP_ASYNC_CANCEL:    "Cancel async operation",
	iouringsyscall.IORING_OP_LINK_TIMEOUT:    "Link timeout",
	iouringsyscall.IORING_OP_CONNECT:         "Connect socket",
	iouringsyscall.IORING_OP_FALLOCATE:       "Preallocate file space",
	iouringsyscall.IORING_OP_OPENAT:          "Open file (relative)",
	iouringsyscall.IORING_OP_CLOSE:           "Close file",
	iouringsyscall.IORING_OP_FILES_UPDATE:    "Update registered files",
	iouringsyscall.IORING_OP_STATX:           "Get file status",
	iouringsyscall.IORING_OP_READ:            "Read",
	iouringsyscall.IORING_OP_WRITE:           "Write",
	iouringsyscall.IORING_OP_FADVISE:         "File access pattern advice",
	iouringsyscall.IORING_OP_MADVISE:         "Memory access pattern advice",
	iouringsyscall.IORING_OP_SEND:            "Send data",
	iouringsyscall.IORING_OP_RECV:            "Receive data",
	iouringsyscall.IORING_OP_OPENAT2:         "Enhanced open file (relative)",
	iouringsyscall.IORING_OP_EPOLL_CTL:       "Epoll control",
	iouringsyscall.IORING_OP_SPLICE:          "Splice data",
	iouringsyscall.IORING_OP_PROVIDE_BUFFERS: "Provide buffers",
	iouringsyscall.IORING_OP_REMOVE_BUFFERS:  "Remove buffers",
	iouringsyscall.IORING_OP_TEE:             "Tee data",
	iouringsyscall.IORING_OP_SHUTDOWN:        "Shutdown connection",
	iouringsyscall.IORING_OP_RENAMEAT:        "Rename file (relative)",
	iouringsyscall.IORING_OP_UNLINKAT:        "Unlink file (relative)",
	iouringsyscall.IORING_OP_MKDIRAT:         "Make directory (relative)",
	iouringsyscall.IORING_OP_SYMLINKAT:       "Create symbolic link (relative)",
	iouringsyscall.IORING_OP_LINKAT:          "Create hard link (relative)",
	iouringsyscall.IORING_OP_MSG_RING:        "Message ring",
	iouringsyscall.IORING_OP_FSETXATTR:       "Set file extended attribute",
	iouringsyscall.IORING_OP_SETXATTR:        "Set extended attribute",
	iouringsyscall.IORING_OP_FGETXATTR:       "Get file extended attribute",
	iouringsyscall.IORING_OP_GETXATTR:        "Get extended attribute",
	iouringsyscall.IORING_OP_SOCKET:          "Create socket",
	iouringsyscall.IORING_OP_URING_CMD:       "io_uring command",
	iouringsyscall.IORING_OP_SEND_ZC:         "Zero-copy send",
}

func GetOpcodeName(opcode uint8) (bool, string) {
	if name, ok := OpcodeMap[opcode]; ok {
		return true, name
	}
	return false, "Unknown operation"
}
