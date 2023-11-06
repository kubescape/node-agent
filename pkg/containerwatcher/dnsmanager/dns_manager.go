package dnsmanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"time"

	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type DNSManager struct {
	cfg                      config.Config
	ctx                      context.Context
	k8sClient                k8sclient.K8sClientInterface
	storageClient            storage.StorageClient
	clusterName              string
	watchedContainerChannels maps.SafeMap[string, chan error] // key is ContainerID
	adressToDomainMap        maps.SafeMap[string, string]
}

var _ DNSManagerClient = (*DNSManager)(nil)

func CreateDNSManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) *DNSManager {
	return &DNSManager{
		cfg:           cfg,
		ctx:           ctx,
		k8sClient:     k8sClient,
		storageClient: storageClient,
		clusterName:   clusterName,
	}
}
func (n *DNSManager) ContainerCallback(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	ctx, span := otel.Tracer("").Start(n.ctx, "NetworkManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
	defer span.End()

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if n.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			return
		}
		go n.handleContainerStarted(ctx, notif.Container, k8sContainerID)

	case containercollection.EventTypeRemoveContainer:
		channel := n.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
		if channel != nil {
			channel <- utils.ContainerHasTerminatedError
		}
		n.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (n *DNSManager) handleContainerStarted(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
	ctx, span := otel.Tracer("").Start(ctx, "DNSManager.handleContainerStarted")
	defer span.End()

	watchedContainer := &utils.WatchedContainerData{
		ContainerID:                              container.Runtime.ContainerID,
		UpdateDataTicker:                         time.NewTicker(n.cfg.InitialDelay),
		SyncChannel:                              make(chan error, 10),
		K8sContainerID:                           k8sContainerID,
		RelevantRealtimeFilesByPackageSourceInfo: map[string]*utils.PackageSourceInfoData{},
		RelevantRealtimeFilesBySPDXIdentifier:    map[v1beta1.ElementID]bool{},
	}
	n.watchedContainerChannels.Set(watchedContainer.ContainerID, watchedContainer.SyncChannel)
}

func (n *DNSManager) SaveNetworkEvent(dnsEvent tracerdnstype.Event) {
	for _, address := range dnsEvent.Addresses {
		n.adressToDomainMap.Set(address, dnsEvent.DNSName)
	}

	logger.L().Debug("DNS event", helpers.Interface("event", dnsEvent))
}
