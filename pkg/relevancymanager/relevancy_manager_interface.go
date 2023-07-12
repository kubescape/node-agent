package relevancymanager

import (
	"context"
	"node-agent/pkg/containerwatcher"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type RelevancyManagerClient interface {
	ReportContainerStarted(ctx context.Context, container *containercollection.Container)
	ReportContainerTerminated(ctx context.Context, container *containercollection.Container)
	ReportFileAccess(ctx context.Context, namespace, pod, container, file string)
	SetContainerHandler(containerHandler containerwatcher.ContainerWatcher)
	StartRelevancyManager(ctx context.Context)
}
