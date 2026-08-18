package networkstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/cenkalti/backoff/v5"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	timeoutDefaultSeconds = 30 // Default timeout for HTTP requests if not set in the config

	// payloadWarnBytes is the size above which a flush logs its shape — well under
	// the broker's 5 MiB limit, far above the ~30 KB fleet mean.
	payloadWarnBytes = 2 << 20
)

type NetworkStream struct {
	networkEventsStorage      armotypes.NetworkStream
	eventsStorageMutex        sync.RWMutex // Mutex to protect access to networkEventsStorage.Containers
	cfg                       config.Config
	ctx                       context.Context
	k8sObjectCache            objectcache.K8sObjectCache
	dnsResolver               dnsmanager.DNSResolver
	k8sInventory              common.K8sInventoryCache
	nodeName                  string
	httpClient                *http.Client
	eventsNotificationChannel chan armotypes.NetworkStream
	dnsSupport                bool
	processTreeManager        processtree.ProcessTreeManager

	// unannouncedEntities holds the entity IDs the event path created because
	// ContainerCallback never announced the container. Nothing will ever remove
	// them — the callback that would deliver the removal is the one that is
	// missing — so snapshotAndClear prunes them once they go quiet.
	unannouncedEntities map[string]struct{}
}

func NewNetworkStream(ctx context.Context, cfg config.Config, k8sObjectCache objectcache.K8sObjectCache, dnsResolver dnsmanager.DNSResolver, nodeName string, eventsNotificationChannel chan armotypes.NetworkStream, dnsSupport bool, processTreeManager processtree.ProcessTreeManager) (*NetworkStream, error) {
	var k8sInventory common.K8sInventoryCache

	if cfg.KubernetesMode {
		var err error
		k8sInventory, err = common.GetK8sInventoryCache()
		if err != nil || k8sInventory == nil {
			return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
		}
		k8sInventory.Start() // We do not stop it here, as we need it to be running for the whole lifetime of the NetworkStream.
	}

	var timeoutSeconds int
	if cfg.Exporters.HTTPExporterConfig != nil && cfg.Exporters.HTTPExporterConfig.TimeoutSeconds > 0 {
		timeoutSeconds = cfg.Exporters.HTTPExporterConfig.TimeoutSeconds
	} else {
		timeoutSeconds = timeoutDefaultSeconds
	}

	ns := NetworkStream{
		networkEventsStorage: armotypes.NetworkStream{
			Entities: make(map[string]armotypes.NetworkStreamEntity),
		},
		cfg:            cfg,
		ctx:            ctx,
		k8sObjectCache: k8sObjectCache,
		dnsResolver:    dnsResolver,
		k8sInventory:   k8sInventory,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
		nodeName:                  nodeName,
		eventsNotificationChannel: eventsNotificationChannel,
		dnsSupport:                dnsSupport,
		processTreeManager:        processTreeManager,
		unannouncedEntities:       make(map[string]struct{}),
	}

	// Create the host entity
	ns.networkEventsStorage.Entities[nodeName] = newHostEntity()

	return &ns, nil
}

// newHostEntity builds the entity that carries the node's own traffic — everything
// not attributable to a container.
func newHostEntity() armotypes.NetworkStreamEntity {
	return armotypes.NetworkStreamEntity{
		Kind:     armotypes.NetworkStreamEntityKindHost,
		Inbound:  make(map[string]armotypes.NetworkStreamEvent),
		Outbound: make(map[string]armotypes.NetworkStreamEvent),
	}
}

func (ns *NetworkStream) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		ns.eventsStorageMutex.Lock()
		// Normalize host container ID to nodeName for consistent entity mapping
		containerID := notif.Container.Runtime.ContainerID
		if utils.IsHostContainer(notif.Container) {
			containerID = ns.nodeName
		}
		entity := armotypes.NetworkStreamEntity{
			Kind: armotypes.NetworkStreamEntityKindContainer,
			NetworkStreamEntityContainer: armotypes.NetworkStreamEntityContainer{
				ContainerName: notif.Container.Runtime.ContainerName,
				ContainerID:   notif.Container.Runtime.ContainerID,
				PodNamespace:  notif.Container.K8s.Namespace,
				PodName:       notif.Container.K8s.PodName,
			},
			Inbound:  make(map[string]armotypes.NetworkStreamEvent),
			Outbound: make(map[string]armotypes.NetworkStreamEvent),
		}
		// The watcher submits this callback to a worker pool, so the event path may
		// already have recorded traffic against this container — a new container's
		// first egress lands in exactly that window. Announcing it supplies the
		// identity; it must not throw the traffic away.
		// Not the node entity: that one exists from construction and is remade by
		// every flush, so it has no unannounced window to rescue, and leaving it
		// alone keeps this callback's node-entity behaviour exactly as it was.
		if existing, ok := ns.networkEventsStorage.Entities[containerID]; ok && containerID != ns.nodeName {
			entity.Inbound = existing.Inbound
			entity.Outbound = existing.Outbound
		}
		ns.networkEventsStorage.Entities[containerID] = entity
		// The container is announced now, so silence no longer means it is gone.
		delete(ns.unannouncedEntities, containerID)
		ns.eventsStorageMutex.Unlock()
		if ns.k8sObjectCache != nil && !utils.IsHostContainer(notif.Container) {
			go ns.enrichWorkloadDetails(notif.Container.Runtime.ContainerID)
		}
	case containercollection.EventTypeRemoveContainer:
		ns.eventsStorageMutex.Lock()
		containerID := notif.Container.Runtime.ContainerID
		if utils.IsHostContainer(notif.Container) {
			containerID = ns.nodeName
		}
		delete(ns.networkEventsStorage.Entities, containerID)
		delete(ns.unannouncedEntities, containerID)
		ns.eventsStorageMutex.Unlock()
	}
}

func (ns *NetworkStream) enrichWorkloadDetails(containerID string) {
	sharedData, err := ns.waitForSharedContainerData(containerID)
	if err != nil {
		logger.L().Error("NetworkStream - failed to get shared container data", helpers.Error(err),
			helpers.String("container ID", containerID))
		return
	}

	if sharedData == nil {
		logger.L().Error("NetworkStream - shared data is nil", helpers.String("container ID", containerID))
		return
	}

	ns.eventsStorageMutex.Lock()
	container, exists := ns.networkEventsStorage.Entities[containerID]
	if !exists {
		ns.eventsStorageMutex.Unlock()
		logger.L().Error("NetworkStream - container no longer exists", helpers.String("container ID", containerID))
		return
	}

	labels := sharedData.InstanceID.GetLabels()
	container.WorkloadName = labels[helpersv1.RelatedNameMetadataKey]
	container.WorkloadKind = labels[helpersv1.RelatedKindMetadataKey]
	ns.networkEventsStorage.Entities[containerID] = container
	ns.eventsStorageMutex.Unlock()
}

func (ns *NetworkStream) waitForSharedContainerData(containerID string) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*objectcache.WatchedContainerData, error) {
		if sharedData := ns.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// Periodically send the network events to the exporter
func (ns *NetworkStream) Start() {
	go func() {
		ticker := time.NewTicker(ns.cfg.NetworkStreamingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ns.ctx.Done():
				logger.L().Info("NetworkStream - stopping")
				return
			case <-ticker.C:
				snapshot := ns.snapshotAndClear()

				// Before the send: once the snapshot is on the channel, its maps belong
				// to the consumer.
				wire := buildWireStream(snapshot)

				// The consumer gets the snapshot WITH its trees — private-node-agent's
				// host network sensor reads outbound.ProcessTree from here. The send
				// blocks so a slow consumer applies backpressure instead of losing
				// traffic, and selects on ctx so it cannot outlive shutdown.
				if ns.eventsNotificationChannel != nil {
					select {
					case ns.eventsNotificationChannel <- *snapshot:
					case <-ns.ctx.Done():
						logger.L().Info("NetworkStream - stopping")
						return
					}
				}

				if err := ns.sendNetworkEvent(wire); err != nil {
					logger.L().Error("NetworkStream - failed to send network events", helpers.Error(err))
				}
				logger.L().Debug("NetworkStream - sent network events")
			}
		}
	}()
}

// snapshotAndClear takes the interval's events and resets the live storage under a
// single lock. Snapshot and clear only; both sends and the tree copies stay outside
// the lock. This path has a history of mutex stalls.
func (ns *NetworkStream) snapshotAndClear() *armotypes.NetworkStream {
	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	// Pruned before the snapshot, so a dead container never reaches a payload at all.
	// An entity the event path created has no container lifecycle behind it, so an
	// interval without traffic is the only "it is gone" signal there is. Keeping it
	// would put a dead container in every later payload — unbounded growth wherever
	// containers churn. A container that is merely idle costs one re-creation on its
	// next event.
	for entityID := range ns.unannouncedEntities {
		entity, ok := ns.networkEventsStorage.Entities[entityID]
		if !ok || (len(entity.Inbound) == 0 && len(entity.Outbound) == 0) {
			delete(ns.networkEventsStorage.Entities, entityID)
			delete(ns.unannouncedEntities, entityID)
		}
	}

	snapshot := snapshotNetworkStream(&ns.networkEventsStorage)

	// Clear the storage
	for entityID, entity := range ns.networkEventsStorage.Entities {
		entity.Inbound = make(map[string]armotypes.NetworkStreamEvent)
		entity.Outbound = make(map[string]armotypes.NetworkStreamEvent)
		ns.networkEventsStorage.Entities[entityID] = entity
	}
	// Re-create the host entity
	ns.networkEventsStorage.Entities[ns.nodeName] = newHostEntity()

	return snapshot
}

func (ns *NetworkStream) ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent) {
	eventType := enrichedEvent.Event.GetEventType()
	switch eventType {
	case utils.NetworkEventType:
		networkEvent, ok := enrichedEvent.Event.(utils.NetworkEvent)
		if !ok {
			return
		}

		dstEndpoint := networkEvent.GetDstEndpoint()
		if networkEvent.GetPktType() == "HOST" && networkEvent.GetPodHostIP() == dstEndpoint.Addr || dstEndpoint.Addr == "127.0.0.1" {
			return // Ignore localhost events
		}

		ns.handleNetworkEvent(networkEvent, &armotypes.ProcessTree{ProcessTree: enrichedEvent.ProcessTree, ContainerID: enrichedEvent.ContainerID})
	case utils.DnsEventType:
		if !ns.dnsSupport {
			return
		}

		dnsEvent, ok := enrichedEvent.Event.(utils.DNSEvent)
		if !ok {
			return
		}
		if !ns.shouldReportDnsEvent(dnsEvent) {
			return
		}

		ns.handleDnsEvent(dnsEvent, &armotypes.ProcessTree{ProcessTree: enrichedEvent.ProcessTree, ContainerID: enrichedEvent.ContainerID})

	default:
		logger.L().Error("NetworkStream - unknown event type", helpers.String("event type", string(eventType)))
	}
}

func (ns *NetworkStream) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	switch eventType {
	case utils.NetworkEventType:
		networkEvent, ok := event.(utils.NetworkEvent)
		if !ok {
			return
		}

		dstEndpoint := networkEvent.GetDstEndpoint()
		if networkEvent.GetPktType() == "HOST" && networkEvent.GetPodHostIP() == dstEndpoint.Addr || dstEndpoint.Addr == "127.0.0.1" {
			return // Ignore localhost events
		}

		ns.handleNetworkEvent(networkEvent, nil)
	case utils.DnsEventType:
		if !ns.dnsSupport {
			return
		}

		dnsEvent, ok := event.(utils.DNSEvent)
		if !ok {
			return
		}
		if !ns.shouldReportDnsEvent(dnsEvent) {
			return
		}

		ns.handleDnsEvent(dnsEvent, nil)

	default:
		logger.L().Error("NetworkStream - unknown event type", helpers.String("event type", string(eventType)))
	}
}

func (ns *NetworkStream) handleDnsEvent(event utils.DNSEvent, processTree *armotypes.ProcessTree) {
	// Resolved before the lock: see processRefFor on the lock ordering.
	ref := ns.processRefFor(event.GetPID())
	outboundKey := getDnsOutboundIdentifier(event.GetDNSName(), ref)

	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	entity, entityId, ok := ns.entityForEventLocked(event.GetContainerID())
	if !ok {
		return
	}

	// We get only DNS response events, so we put them in the outbound map
	if _, exists := entity.Outbound[outboundKey]; exists {
		// If the event already exists, we can skip it
		return
	}

	networkEvent := armotypes.NetworkStreamEvent{
		Timestamp: time.Unix(0, int64(event.GetTimestamp())),
		DNSName:   event.GetDNSName(),
		Port:      int32(event.GetDstPort()),
		Protocol:  armotypes.NetworkStreamEventProtocolDNS,
		Kind:      armotypes.EndpointKindRaw,
	}

	processTree = ns.getProcessTreeByPid(event.GetPID(), event.GetComm(), processTree)
	networkEvent.ProcessTree = processTree
	networkEvent.ProcessRef = ref

	entity.Outbound[outboundKey] = networkEvent
	ns.networkEventsStorage.Entities[entityId] = entity
}

func (ns *NetworkStream) shouldReportDnsEvent(dnsEvent utils.DNSEvent) bool {
	dnsName := dnsEvent.GetDNSName()

	if dnsName == "" {
		return false
	}

	if strings.HasSuffix(dnsName, "in-addr.arpa.") {
		return false
	}

	if strings.HasSuffix(dnsName, "svc.cluster.local.") {
		return false
	}

	return true
}

func (ns *NetworkStream) handleNetworkEvent(event utils.NetworkEvent, processTree *armotypes.ProcessTree) {
	ref := ns.processRefFor(event.GetPID())
	endpointID := getNetworkEndpointIdentifier(event, ref)

	ns.eventsStorageMutex.Lock()
	defer ns.eventsStorageMutex.Unlock()

	entity, entityId, ok := ns.entityForEventLocked(event.GetContainerID())
	if !ok {
		return
	}

	if event.GetPktType() == "OUTGOING" {
		if _, exists := entity.Outbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event, processTree, ref)
		entity.Outbound[endpointID] = networkEvent
	} else {
		if _, exists := entity.Inbound[endpointID]; exists {
			// If the event already exists, we can skip it
			return
		}
		networkEvent := ns.buildNetworkEvent(event, processTree, ref)
		entity.Inbound[endpointID] = networkEvent
	}
	ns.networkEventsStorage.Entities[entityId] = entity
}

// entityForEventLocked resolves the entity an event belongs to, reporting false when
// the event has nowhere to go and must be dropped.
//
// Only traffic that is not a container's — no container ID, or the host sentinel —
// collapses onto the node entity. Everything else keys by container ID. That used to
// depend on the Kubernetes object cache being present, so on ECS and host installs
// every container's traffic was merged into the node and no per-container entity
// existed at all.
//
// Outside Kubernetes the entity is also created here, which is what makes the keying
// useful there: nothing announces a container to this package, so an event for an
// unknown entity was simply dropped and no container entity could ever exist. Such
// entities are recorded in unannouncedEntities, because they are the ones
// snapshotAndClear has to prune.
//
// In Kubernetes the container lifecycle is reliable, so a missing entity means the
// container was removed or is ignored, not that it was never announced — and the
// collection publishes the removal BEFORE the container leaves it, so events keep
// arriving for a container that is already gone. Creating one there would emit a
// container with no pod or workload identity for a pod that no longer exists, so
// Kubernetes keeps dropping.
//
// Callers must hold eventsStorageMutex for writing.
func (ns *NetworkStream) entityForEventLocked(containerID string) (armotypes.NetworkStreamEntity, string, bool) {
	entityID := containerID
	if entityID == "" || entityID == armotypes.HostContainerID {
		entityID = ns.nodeName
	}

	if entity, ok := ns.networkEventsStorage.Entities[entityID]; ok {
		return entity, entityID, true
	}

	// The node entity is created at construction and re-created by every flush, so
	// it is only missing if the host container was removed in between. Restore it as
	// the host rather than inventing a container whose ID is the node's name, and
	// leave it unprunable.
	if entityID == ns.nodeName {
		entity := newHostEntity()
		ns.networkEventsStorage.Entities[entityID] = entity
		return entity, entityID, true
	}

	if ns.cfg.KubernetesMode {
		logger.L().Error("NetworkStream - entity not found", helpers.String("entity ID", entityID))
		return armotypes.NetworkStreamEntity{}, entityID, false
	}

	entity := armotypes.NetworkStreamEntity{
		Kind: armotypes.NetworkStreamEntityKindContainer,
		NetworkStreamEntityContainer: armotypes.NetworkStreamEntityContainer{
			ContainerID: entityID,
		},
		Inbound:  make(map[string]armotypes.NetworkStreamEvent),
		Outbound: make(map[string]armotypes.NetworkStreamEvent),
	}
	ns.networkEventsStorage.Entities[entityID] = entity
	ns.unannouncedEntities[entityID] = struct{}{}
	return entity, entityID, true
}

func (ns *NetworkStream) buildNetworkEvent(event utils.NetworkEvent, processTree *armotypes.ProcessTree, ref *armotypes.ProcessRef) armotypes.NetworkStreamEvent {
	var domain string
	var ok bool
	dstEndpoint := event.GetDstEndpoint()
	if event.GetPktType() == "OUTGOING" {
		domain, ok = ns.dnsResolver.ResolveIPAddress(dstEndpoint.Addr)
		if !ok {
			// Try to resolve the domain name
			domains, err := net.LookupAddr(dstEndpoint.Addr)
			if err != nil {
				domain = ""
			} else {
				if len(domains) > 0 {
					domain = domains[0]
				}
			}
		}
	} else {
		domain, _ = ns.dnsResolver.ResolveIPAddress(dstEndpoint.Addr)
	}

	networkEvent := armotypes.NetworkStreamEvent{
		Timestamp: time.Unix(0, int64(event.GetTimestamp())),
		IPAddress: dstEndpoint.Addr,
		DNSName:   domain,
		Port:      int32(event.GetDstPort()),
		Protocol:  armotypes.NetworkStreamEventProtocol(event.GetProto()),
	}

	// The inventory is only built in Kubernetes mode. Outside it a pod- or
	// service-kind endpoint leaves the connection unenriched rather than
	// dereferencing a nil interface.
	if ns.k8sInventory != nil {
		switch armotypes.EndpointKind(dstEndpoint.Kind) {
		case armotypes.EndpointKindPod:
			slimPod := ns.k8sInventory.GetPodByIp(dstEndpoint.Addr)
			if slimPod != nil {
				networkEvent.PodName = slimPod.Name
				networkEvent.PodNamespace = slimPod.Namespace

				workloadKind := ""
				workloadName := ""

				if len(slimPod.OwnerReferences) > 0 {
					workloadKind = slimPod.OwnerReferences[0].Kind
					if WorkloadKind(workloadKind) == ReplicaSet {
						workloadKind = string(Deployment)
					}
					// TODO: handle similar cases for CronJob -> Job -> Pod.
					workloadName = extractWorkloadName(slimPod.Name, WorkloadKind(workloadKind))
				}

				networkEvent.WorkloadName = workloadName
				networkEvent.WorkloadKind = workloadKind
				networkEvent.WorkloadNamespace = slimPod.Namespace
			}
		case armotypes.EndpointKindService:
			slimService := ns.k8sInventory.GetSvcByIp(dstEndpoint.Addr)
			if slimService != nil {
				networkEvent.ServiceName = slimService.Name
				networkEvent.ServiceNamespace = slimService.Namespace
			}
		}
	}

	networkEvent.Kind = armotypes.EndpointKind(dstEndpoint.Kind)

	processTree = ns.getProcessTreeByPid(event.GetPID(), event.GetComm(), processTree)
	networkEvent.ProcessTree = processTree
	networkEvent.ProcessRef = ref

	return networkEvent
}

func (ns *NetworkStream) sendNetworkEvent(networkStream *armotypes.NetworkStream) error {
	if !ns.cfg.KubernetesMode || ns.cfg.Exporters.HTTPExporterConfig == nil {
		return nil
	}

	if isEmptyNetworkStream(networkStream) {
		logger.L().Debug("no events in network stream, skipping")
		return nil
	}

	// create a GenericCRD with NetworkStream as Spec
	crd := armotypes.GenericCRD[armotypes.NetworkStream]{
		Kind:       "NetworkStreams",
		ApiVersion: "kubescape.io/v1",
		Metadata: armotypes.Metadata{
			Name: ns.nodeName,
		},
		Spec: *networkStream,
	}
	// create the JSON representation of the crd
	bodyBytes, err := json.Marshal(crd)
	if err != nil {
		return fmt.Errorf("marshal network stream: %w", err)
	}
	// Quiet at the ~30 KB fleet mean; reports the tail approaching the broker's 5 MiB
	// limit. Note the synchronizer envelope is base64, a further x1.333 on this size.
	if len(bodyBytes) > payloadWarnBytes {
		logger.L().Warning("NetworkStream - large payload",
			helpers.Int("bytes", len(bodyBytes)),
			helpers.Int("entities", len(networkStream.Entities)),
			helpers.Int("connections", countConnections(networkStream)),
			helpers.Int("processTrees", len(networkStream.Processes)))
	}
	bodyReader := bytes.NewReader(bodyBytes)
	// prepare the request
	req, err := http.NewRequest(ns.cfg.Exporters.HTTPExporterConfig.Method,
		ns.cfg.Exporters.HTTPExporterConfig.URL+"/v1/networkstreams", bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for _, header := range ns.cfg.Exporters.HTTPExporterConfig.Headers {
		req.Header.Set(header.Key, header.Value)
	}
	// send the request
	resp, err := ns.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status code: %d", resp.StatusCode)
	}
	// discard the body
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("clear response body: %w", err)
	}
	return nil
}

// getNetworkEndpointIdentifier builds the per-batch connection key. The ref is
// APPENDED, never reordered: a nil ref leaves the key byte-identical to the
// pre-attribution format, and an attributed key carries two more components, so the
// two forms cannot collide.
func getNetworkEndpointIdentifier(event utils.NetworkEvent, ref *armotypes.ProcessRef) string {
	id := fmt.Sprintf("%s/%d/%s", event.GetDstEndpoint().Addr, event.GetDstPort(), event.GetProto())
	if ref != nil {
		id += "/" + ref.String()
	}
	return id
}

// getDnsOutboundIdentifier keys a DNS query by name plus the querying process, so
// two processes resolving one domain no longer overwrite each other.
func getDnsOutboundIdentifier(dnsName string, ref *armotypes.ProcessRef) string {
	if ref == nil {
		return dnsName
	}
	return dnsName + "/" + ref.String()
}

// processRefFor builds the wire identity of the process behind an event.
//
// StartTimeNs is boot-relative NANOSECONDS, emitted VERBATIM — never scale it. A
// division here still joins correctly within one message while breaking identity
// across messages by seven orders of magnitude, so the bug is nearly invisible.
// See docs/features/process-start-time.md.
//
// Zero is legal and means unknown, leaving pid-only identity; emit the ref anyway.
//
// Call this BEFORE taking eventsStorageMutex — the lookup takes the process tree's
// read lock, and holding both would add a storage->tree lock-order edge.
func (ns *NetworkStream) processRefFor(pid uint32) *armotypes.ProcessRef {
	if pid == 0 || ns.processTreeManager == nil {
		return nil // nothing to attribute
	}
	return &armotypes.ProcessRef{PID: pid, StartTimeNs: ns.processTreeManager.GetProcessBootTimeNs(pid)}
}

func countConnections(networkStream *armotypes.NetworkStream) int {
	total := 0
	for _, entity := range networkStream.Entities {
		total += len(entity.Inbound) + len(entity.Outbound)
	}
	return total
}

func isEmptyNetworkStream(networkStream *armotypes.NetworkStream) bool {
	if len(networkStream.Entities) == 0 {
		return true
	}
	for _, entity := range networkStream.Entities {
		if len(entity.Inbound) > 0 || len(entity.Outbound) > 0 {
			return false
		}
	}
	return true
}

// snapshotNetworkStream returns a NetworkStream sharing no mutable state with the live
// storage, so eventsStorageMutex can be released before either send.
//
// Tree POINTERS are shared rather than walked, which keeps this to cheap struct copies.
// That is safe only because a tree is immutable once attached to an event — anything
// that would modify one copies it first.
func snapshotNetworkStream(src *armotypes.NetworkStream) *armotypes.NetworkStream {
	dst := &armotypes.NetworkStream{
		Entities: make(map[string]armotypes.NetworkStreamEntity, len(src.Entities)),
	}
	for entityID, entity := range src.Entities {
		e := entity // struct copy: scalar entity metadata
		e.Inbound = copyEvents(entity.Inbound)
		e.Outbound = copyEvents(entity.Outbound)
		dst.Entities[entityID] = e
	}
	return dst
}

func copyEvents(events map[string]armotypes.NetworkStreamEvent) map[string]armotypes.NetworkStreamEvent {
	out := make(map[string]armotypes.NetworkStreamEvent, len(events))
	for key, event := range events {
		out[key] = event
	}
	return out
}

func (ns *NetworkStream) getProcessTreeByPid(pid uint32, comm string, processTree *armotypes.ProcessTree) *armotypes.ProcessTree {
	if processTree != nil {
		return processTree
	}

	logger.L().Debug("NetworkStream - getting process tree by pid", helpers.Int("pid", int(pid)), helpers.String("comm", comm))

	return &armotypes.ProcessTree{
		ProcessTree: armotypes.Process{
			PID:  pid,
			Comm: comm,
		},
	}
}
