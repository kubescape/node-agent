package relevancymanager

import (
	"context"
	"errors"
	"node-agent/pkg/containerwatcher"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

var (
	ContainerHasTerminatedError = errors.New("container has terminated")
	IncompleteSBOMError         = errors.New("incomplete SBOM")
)

type RelevancyManagerClient interface {
	ReportContainerStarted(ctx context.Context, container *containercollection.Container)
	ReportContainerTerminated(ctx context.Context, container *containercollection.Container)
	ReportFileAccess(ctx context.Context, namespace, pod, container, file string)
	SetContainerHandler(containerHandler containerwatcher.ContainerWatcher)
}
