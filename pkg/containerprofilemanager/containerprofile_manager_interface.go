package containerprofilemanager

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportCapability(containerID, capability string)
	ReportFileExec(containerID string, event utils.ExecEvent)
	ReportProcfsExec(containerID string, path string, argv []string)
	ReportFileOpen(containerID string, event utils.OpenEvent)
	ReportHTTPEvent(containerID string, event utils.HttpEvent)
	ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool)
	ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack)
	ReportSymlinkEvent(containerID string, event utils.LinkEvent)
	ReportHardlinkEvent(containerID string, event utils.LinkEvent)
	ReportNetworkEvent(containerID string, event utils.NetworkEvent)
	// ReportSyscalls reports a batch of syscalls for a container in a single operation. The
	// syscall tracer bypasses the generic per-event pipeline entirely for this method (see
	// SyscallTracer.callback), so this is the only entry point for syscall data -
	// ContainerProfileManagerClient intentionally has no single-syscall equivalent.
	ReportSyscalls(containerID string, syscalls []string)
	ReportDroppedEvent(containerID string)
	RegisterForContainerEndOfLife(notificationChannel chan *containercollection.Container)
	OnQueueError(profile *v1beta1.ContainerProfile, containerID string, err error)
	// SetSyscallFlusher registers the legacy best-effort flush request.
	SetSyscallFlusher(flush func())
}

type Enricher interface {
	EnrichEvent(containerID string, event utils.EnrichEvent, callID string)
}

// SyscallFlushRegistrar optionally supports acknowledged final syscall delivery.
// A callback must honor cancellation and return nil only after ReportSyscalls.
type SyscallFlushRegistrar interface {
	SetSyscallFlusherWithContext(flush func(context.Context) error)
}
