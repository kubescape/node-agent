package relevancymanager

import (
	"context"
	"node-agent/pkg/containerwatcher"
)

type RelevancyManagerClient interface {
	ReportContainerStarted(ctx context.Context, contEvent containerwatcher.ContainerEvent)
	ReportContainerTerminated(ctx context.Context, contEvent containerwatcher.ContainerEvent)
	ReportFileAccess(ctx context.Context, namespace, pod, container, file string)
	SetContainerHandler(containerHandler containerwatcher.ContainerWatcher)
	StartRelevancyManager(ctx context.Context)
}
