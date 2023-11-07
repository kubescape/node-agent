package dnsmanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManager struct {
	cfg config.Config
	ctx context.Context
	// k8sClient                k8sclient.K8sClientInterface
	// storageClient            storage.StorageClient
	// clusterName              string
	// watchedContainerChannels maps.SafeMap[string, chan error] // key is ContainerID
	addressToDomainMap maps.SafeMap[string, string] // this map is used to resolve IP address to domain name
}

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) *DNSManager {
	return &DNSManager{
		cfg: cfg,
		ctx: ctx,
		// k8sClient:     k8sClient,
		// storageClient: storageClient,
		// clusterName:   clusterName,
	}
}

// func (dn *DNSManager) ContainerCallback(notif containercollection.PubSubEvent) {
// 	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
// 	ctx, span := otel.Tracer("").Start(dn.ctx, "NetworkManager.ContainerCallback", trace.WithAttributes(attribute.String("containerID", notif.Container.Runtime.ContainerID), attribute.String("k8s workload", k8sContainerID)))
// 	defer span.End()

// 	switch notif.Type {
// 	case containercollection.EventTypeAddContainer:
// 		if dn.watchedContainerChannels.Has(notif.Container.Runtime.ContainerID) {
// 			logger.L().Debug("container already exist in memory", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
// 			return
// 		}
// 		go dn.handleContainerStarted(ctx, notif.Container, k8sContainerID)

// 	case containercollection.EventTypeRemoveContainer:
// 		channel := dn.watchedContainerChannels.Get(notif.Container.Runtime.ContainerID)
// 		if channel != nil {
// 			channel <- utils.ContainerHasTerminatedError
// 		}
// 		dn.watchedContainerChannels.Delete(notif.Container.Runtime.ContainerID)
// 	}
// }

// func (dn *DNSManager) handleContainerStarted(ctx context.Context, container *containercollection.Container, k8sContainerID string) {
// 	ctx, span := otel.Tracer("").Start(ctx, "DNSManager.handleContainerStarted")
// 	defer span.End()

// 	watchedContainer := &utils.WatchedContainerData{
// 		ContainerID:                              container.Runtime.ContainerID,
// 		UpdateDataTicker:                         time.NewTicker(dn.cfg.InitialDelay),
// 		SyncChannel:                              make(chan error, 10),
// 		K8sContainerID:                           k8sContainerID,
// 		RelevantRealtimeFilesByPackageSourceInfo: map[string]*utils.PackageSourceInfoData{},
// 		RelevantRealtimeFilesBySPDXIdentifier:    map[v1beta1.ElementID]bool{},
// 	}
// 	dn.watchedContainerChannels.Set(watchedContainer.ContainerID, watchedContainer.SyncChannel)
// }

func (dn *DNSManager) SaveNetworkEvent(podName string, dnsEvent tracerdnstype.Event) {
	for _, address := range dnsEvent.Addresses {
		dn.addressToDomainMap.Set(address, dnsEvent.DNSName)
	}
}

func (dn *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := dn.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}
