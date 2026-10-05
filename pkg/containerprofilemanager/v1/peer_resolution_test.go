package containerprofilemanager

import (
	"errors"
	"testing"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type stubK8sObjectCache struct {
	objectcache.K8sObjectCacheMock
	pods         []*corev1.Pod
	getPodsCalls int
}

func (s *stubK8sObjectCache) GetPods() []*corev1.Pod {
	s.getPodsCalls++
	return s.pods
}

func (s *stubK8sObjectCache) GetPodByIP(ip string) *corev1.Pod {
	for _, pod := range s.pods {
		if pod != nil && pod.Status.PodIP == ip {
			return pod
		}
	}
	return nil
}

type mockK8sInventory struct {
	podsByIP map[string]*common.SlimPod
	svcsByIP map[string]*common.SlimService
}

func newMockK8sInventory() *mockK8sInventory {
	return &mockK8sInventory{
		podsByIP: make(map[string]*common.SlimPod),
		svcsByIP: make(map[string]*common.SlimService),
	}
}

func (m *mockK8sInventory) Start() {}
func (m *mockK8sInventory) Stop()  {}

func (m *mockK8sInventory) GetPods() []*common.SlimPod {
	var pods []*common.SlimPod
	for _, p := range m.podsByIP {
		pods = append(pods, p)
	}
	return pods
}

func (m *mockK8sInventory) GetPodByName(namespace string, name string) *common.SlimPod {
	for _, p := range m.podsByIP {
		if p.Namespace == namespace && p.Name == name {
			return p
		}
	}
	return nil
}

func (m *mockK8sInventory) GetPodByIp(ip string) *common.SlimPod {
	if m.podsByIP == nil {
		return nil
	}
	return m.podsByIP[ip]
}

func (m *mockK8sInventory) GetSvcs() []*common.SlimService {
	var svcs []*common.SlimService
	for _, s := range m.svcsByIP {
		svcs = append(svcs, s)
	}
	return svcs
}

func (m *mockK8sInventory) GetSvcByName(namespace string, name string) *common.SlimService {
	for _, s := range m.svcsByIP {
		if s.Namespace == namespace && s.Name == name {
			return s
		}
	}
	return nil
}

func (m *mockK8sInventory) GetSvcByIp(ip string) *common.SlimService {
	if m.svcsByIP == nil {
		return nil
	}
	return m.svcsByIP[ip]
}

func TestCreateNetworkNeighbor_RawPodIP_ResolvedViaK8sInventory(t *testing.T) {
	inv := newMockK8sInventory()
	inv.podsByIP["10.244.0.14"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "wikijs-5b7c844697-x9k2v",
			Namespace: "default",
			Labels: map[string]string{
				"app":               "wikijs",
				"pod-template-hash": "5b7c844697",
			},
		},
		Spec: common.SlimPodSpec{
			HostNetwork: false,
		},
		Status: common.SlimPodStatus{
			PodIP: "10.244.0.14",
		},
	}

	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     3306,
		Protocol: "tcp",
		PktType:  utils.HostPktType, // ingress to mariadb
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.244.0.14",
		},
	}

	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, inv, nil, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, InternalTrafficType, string(neighbor.Type))
	assert.Empty(t, neighbor.IPAddress, "pod neighbor must not have raw ipAddress set")
	require.NotNil(t, neighbor.PodSelector)
	assert.Equal(t, map[string]string{"app": "wikijs"}, neighbor.PodSelector.MatchLabels)
	assert.NotContains(t, neighbor.PodSelector.MatchLabels, "pod-template-hash")
	assert.Nil(t, neighbor.NamespaceSelector, "same namespace should have nil namespaceSelector")
	require.Len(t, neighbor.Ports, 1)
	assert.Equal(t, int32(3306), *neighbor.Ports[0].Port)
}

func TestCreateNetworkNeighbor_RawPodIP_CrossNamespace(t *testing.T) {
	inv := newMockK8sInventory()
	inv.podsByIP["10.244.0.14"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "wikijs-abcde",
			Namespace: "client-ns",
			Labels: map[string]string{
				"app": "wikijs",
			},
		},
		Spec: common.SlimPodSpec{
			HostNetwork: false,
		},
		Status: common.SlimPodStatus{
			PodIP: "10.244.0.14",
		},
	}

	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     3306,
		Protocol: "tcp",
		PktType:  utils.HostPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.244.0.14",
		},
	}

	neighbor := cd.createNetworkNeighbor("", rawEvent, "server-ns", nil, nil, inv, nil, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, InternalTrafficType, string(neighbor.Type))
	require.NotNil(t, neighbor.PodSelector)
	assert.Equal(t, map[string]string{"app": "wikijs"}, neighbor.PodSelector.MatchLabels)
	require.NotNil(t, neighbor.NamespaceSelector)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "client-ns"}, neighbor.NamespaceSelector.MatchLabels)
}

func TestCreateNetworkNeighbor_RawPodIP_ResolvedViaK8sObjectCache(t *testing.T) {
	mockCache := &stubK8sObjectCache{
		pods: []*corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wikijs-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "wikijs"},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					PodIP: "10.244.0.14",
				},
			},
		},
	}

	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     3306,
		Protocol: "tcp",
		PktType:  utils.HostPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.244.0.14",
		},
	}

	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, nil, mockCache, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, InternalTrafficType, string(neighbor.Type))
	require.NotNil(t, neighbor.PodSelector)
	assert.Equal(t, map[string]string{"app": "wikijs"}, neighbor.PodSelector.MatchLabels)
	require.Zero(t, mockCache.getPodsCalls, "fallback lookup must use the IP index")
}

func TestCreateNetworkNeighbor_RawServiceIP_ResolvedViaK8sInventory(t *testing.T) {
	inv := newMockK8sInventory()
	inv.svcsByIP["10.96.0.42"] = &common.SlimService{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "api-svc",
			Namespace: "default",
		},
		Spec: common.SlimServiceSpec{
			ClusterIP: "10.96.0.42",
		},
	}

	service := newServiceWorkload("api-svc", map[string]any{"app": "api"}, map[string]any{
		"port": 80, "targetPort": 8080, "protocol": "TCP",
	})
	client := &servicePortTestClient{
		service:    service,
		kubeClient: fake.NewClientset(),
	}

	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     80,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.96.0.42",
		},
	}

	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", client, nil, inv, nil, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, InternalTrafficType, string(neighbor.Type))
	require.NotNil(t, neighbor.PodSelector)
	assert.Equal(t, map[string]string{"app": "api"}, neighbor.PodSelector.MatchLabels)
}

func TestCreateNetworkNeighbor_RawPrivateIP_DeferredOnIntermediateFlush(t *testing.T) {
	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     3306,
		Protocol: "tcp",
		PktType:  utils.HostPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.244.0.14",
		},
	}

	// 1. First flush: IP is private (10.244.0.14) and inventory does not have it yet.
	// Intermediate flush (forceSend = false).
	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, nil, nil, false)
	assert.Nil(t, neighbor, "raw private IP should be deferred on first intermediate flush")
	require.NotNil(t, cd.deferredNetworks)
	assert.True(t, cd.deferredNetworks.Contains(rawEvent))

	// 2. emptyEvents preserves deferred networks for next flush
	cd.emptyEvents()
	assert.Nil(t, cd.deferredNetworks)
	require.NotNil(t, cd.networks)
	assert.True(t, cd.networks.Contains(rawEvent))
	require.NotNil(t, cd.prevDeferredNetworks)
	assert.True(t, cd.prevDeferredNetworks.Contains(rawEvent))

	// 3. Second flush: inventory now has the pod!
	inv := newMockK8sInventory()
	inv.podsByIP["10.244.0.14"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "wikijs",
			Namespace: "default",
			Labels:    map[string]string{"app": "wikijs"},
		},
		Status: common.SlimPodStatus{PodIP: "10.244.0.14"},
	}

	neighbor = cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, inv, nil, false)
	require.NotNil(t, neighbor, "re-resolved to pod on second flush")
	assert.Equal(t, InternalTrafficType, string(neighbor.Type))
	assert.Equal(t, map[string]string{"app": "wikijs"}, neighbor.PodSelector.MatchLabels)
}

func TestCreateNetworkNeighbor_RawPrivateIP_EmittedExternalIfNeverResolves(t *testing.T) {
	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     3306,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "10.50.1.20", // off-cluster private IP
		},
	}

	// Flush 1: deferred
	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, nil, nil, false)
	assert.Nil(t, neighbor)

	// emptyEvents moves it to prevDeferredNetworks
	cd.emptyEvents()

	// Flush 2: already deferred once, now emitted as external
	neighbor = cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, nil, nil, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, ExternalTrafficType, string(neighbor.Type))
	assert.Equal(t, "10.50.1.20", neighbor.IPAddress)
}

func TestCreateNetworkNeighbor_PublicIP_EmittedExternalImmediately(t *testing.T) {
	cd := &containerData{}
	rawEvent := NetworkEvent{
		Port:     443,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindRaw,
			IPAddress: "93.184.216.34", // public IP
		},
	}

	neighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil, nil, nil, false)
	require.NotNil(t, neighbor)
	assert.Equal(t, ExternalTrafficType, string(neighbor.Type))
	assert.Equal(t, "93.184.216.34", neighbor.IPAddress)
	assert.Nil(t, cd.deferredNetworks)
}

func TestReportNetworkEvent_ImmediateResolutionWhenAvailableInInventory(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")
	inv := newMockK8sInventory()
	inv.podsByIP["10.244.0.14"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "wikijs",
			Namespace: "default",
			Labels:    map[string]string{"app": "wikijs"},
		},
		Status: common.SlimPodStatus{PodIP: "10.244.0.14"},
	}
	cpm.SetK8sInventory(inv)

	event := &utils.StructEvent{
		DstEndpoint: types.L3Endpoint{
			Addr: "10.244.0.14",
			Kind: types.EndpointKindRaw, // inspector gadget emitted raw
		},
		DstPort: 3306,
		Proto:   "tcp",
		PktType: utils.HostPktType,
	}

	cpm.ReportNetworkEvent("container1", event)

	// Verify that networks stored the event directly resolved to EndpointKindPod
	slice := entry.data.networks.ToSlice()
	require.Len(t, slice, 1)
	assert.Equal(t, EndpointKindPod, slice[0].Destination.Kind)
	assert.Equal(t, "wikijs", slice[0].Destination.Name)
	assert.Equal(t, map[string]string{"app": "wikijs"}, slice[0].GetDestinationPodLabels())
}

func TestMonitoring_ReResolutionAtProfileFlush(t *testing.T) {
	cpm, entry := newTestManager(t, "container1")
	inv := newMockK8sInventory()
	cpm.SetK8sInventory(inv)

	// Step 1: Network event arrived when pod was NOT yet in inventory
	event := &utils.StructEvent{
		DstEndpoint: types.L3Endpoint{
			Addr: "10.244.0.14",
			Kind: types.EndpointKindRaw,
		},
		DstPort: 3306,
		Proto:   "tcp",
		PktType: utils.HostPktType,
	}
	cpm.ReportNetworkEvent("container1", event)

	// Event is stored as raw
	slice := entry.data.networks.ToSlice()
	require.Len(t, slice, 1)
	assert.Equal(t, EndpointKindRaw, slice[0].Destination.Kind)

	// Step 2: Informer catches up before saveProfile flush!
	inv.podsByIP["10.244.0.14"] = &common.SlimPod{
		SlimObjectMeta: common.SlimObjectMeta{
			Name:      "wikijs-789",
			Namespace: "default",
			Labels:    map[string]string{"app": "wikijs"},
		},
		Status: common.SlimPodStatus{PodIP: "10.244.0.14"},
	}

	// Step 3: Profile generation resolves raw peer via k8sInventory
	ingress := entry.data.getIngressNetworkNeighbors("mariadb", "default", nil, nil, cpm.k8sInventory, cpm.k8sObjectCache, false)
	require.Len(t, ingress, 1)
	assert.Equal(t, InternalTrafficType, string(ingress[0].Type))
	assert.Empty(t, ingress[0].IPAddress)
	require.NotNil(t, ingress[0].PodSelector)
	assert.Equal(t, map[string]string{"app": "wikijs"}, ingress[0].PodSelector.MatchLabels)
}

func TestNetworkNeighbors_MergeDistinctPortsAfterResolution(t *testing.T) {
	for _, direction := range []string{utils.HostPktType, utils.OutgoingPktType} {
		t.Run(direction, func(t *testing.T) {
			inv := newMockK8sInventory()
			inv.podsByIP["10.244.0.14"] = &common.SlimPod{SlimObjectMeta: common.SlimObjectMeta{
				Name: "peer", Namespace: "default", Labels: map[string]string{"app": "peer"},
			}}
			cd := &containerData{networks: mapset.NewSet[NetworkEvent]()}
			raw := NetworkEvent{Port: 80, Protocol: "tcp", PktType: direction,
				Destination: Destination{Kind: EndpointKindRaw, IPAddress: "10.244.0.14"}}
			cd.networks.Add(raw)
			resolved := raw
			resolveEndpoint(&resolved, inv, nil)
			cd.networks.Add(resolved) // Same peer and port from a later, resolved observation.
			resolved.Port = 443
			cd.networks.Add(resolved)
			resolved.Port = 80
			resolved.Protocol = "udp"
			cd.networks.Add(resolved)
			var neighbors []v1beta1.NetworkNeighbor
			if direction == utils.HostPktType {
				neighbors = cd.getIngressNetworkNeighbors("", "default", nil, nil, inv, nil, false)
			} else {
				neighbors = cd.getEgressNetworkNeighbors("", "default", nil, nil, inv, nil, false)
			}
			require.Len(t, neighbors, 1)
			names := make([]string, 0, len(neighbors[0].Ports))
			for _, port := range neighbors[0].Ports {
				names = append(names, port.Name)
			}
			require.ElementsMatch(t, []string{"tcp-80", "tcp-443", "udp-80"}, names)
		})
	}
}

func TestCreateNetworkNeighbor_PreservesSnapshotEqualToObservedPort(t *testing.T) {
	event := serviceNetworkEvent(80, "tcp")
	client := &servicePortTestClient{
		service: newServiceWorkload("api", map[string]any{"app": "api"}, map[string]any{
			"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
		}),
		kubeClient: fake.NewClientset(newEndpointSlice("api-new", "api", discoveryv1.EndpointPort{
			Name: ptr.To("web"), Port: ptr.To(int32(8080)), Protocol: ptr.To(corev1.ProtocolTCP),
		})),
	}
	cd := &containerData{servicePorts: map[NetworkEvent][]uint16{event: {80}}}
	neighbor := cd.createNetworkNeighbor("", event, "default", client, nil, nil, nil, false)
	require.NotNil(t, neighbor)
	require.Equal(t, []int32{80}, networkPortValues(neighbor.Ports))
	require.Empty(t, client.kubeClient.Actions(), "cached snapshots must not query changed EndpointSlices")
}

func TestCreateNetworkNeighbor_ServicePromotionPreservesRawFallback(t *testing.T) {
	for _, lookupFailure := range []bool{false, true} {
		name := "selectorless service"
		if lookupFailure {
			name = "lookup failure"
		}
		t.Run(name, func(t *testing.T) {
			inv := newMockK8sInventory()
			inv.svcsByIP["10.96.0.42"] = &common.SlimService{SlimObjectMeta: common.SlimObjectMeta{Name: "api", Namespace: "default"}}
			client := &servicePortTestClient{service: newServiceWorkload("api", nil)}
			if lookupFailure {
				client.getErr = errors.New("transient lookup failure")
			}
			for _, kind := range []EndpointKind{EndpointKindRaw, EndpointKindService} {
				event := NetworkEvent{Port: 80, Protocol: "tcp", PktType: utils.OutgoingPktType,
					Destination: Destination{Kind: kind, IPAddress: "10.96.0.42", Namespace: "default", Name: "api"}}
				cd := &containerData{}
				require.Nil(t, cd.createNetworkNeighbor("", event, "default", client, nil, inv, nil, false))
				require.NotNil(t, cd.deferredNetworks, "failed promotion must retain the observation")
				require.True(t, cd.deferredNetworks.Contains(event))
				cd.emptyEvents()
				neighbor := cd.createNetworkNeighbor("", event, "default", client, nil, inv, nil, false)
				require.NotNil(t, neighbor, "retry is bounded to one flush")
				require.Equal(t, ExternalTrafficType, string(neighbor.Type))
				require.Equal(t, "10.96.0.42", neighbor.IPAddress)
				require.Equal(t, []int32{80}, networkPortValues(neighbor.Ports))
				final := (&containerData{}).createNetworkNeighbor("", event, "default", client, nil, inv, nil, true)
				require.NotNil(t, final, "forced final flush must preserve raw IP")
				require.Equal(t, "10.96.0.42", final.IPAddress)
			}
		})
	}
}

func TestEmptyEvents_RetainsDeferredServicePortSnapshot(t *testing.T) {
	event := serviceNetworkEvent(80, "tcp")
	event.Destination.IPAddress = "10.96.0.42"
	discarded := serviceNetworkEvent(443, "tcp")
	cd := &containerData{servicePorts: map[NetworkEvent][]uint16{event: {8080, 9090}, discarded: {8443}}}
	client := &servicePortTestClient{getErr: errors.New("transient lookup failure")}
	require.Nil(t, cd.createNetworkNeighbor("", event, "default", client, nil, nil, nil, false))
	cd.emptyEvents()
	require.Equal(t, map[NetworkEvent][]uint16{event: {8080, 9090}}, cd.servicePorts)
	require.Equal(t, int64(size.Of(event)+networkNeighborIncrement(cd, event)), cd.size.Load())

	// EndpointSlices change while the Service lookup recovers.
	client.getErr = nil
	client.service = newServiceWorkload("api", map[string]any{"app": "api"}, map[string]any{
		"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
	})
	client.kubeClient = fake.NewClientset(newEndpointSlice("api-new", "api", discoveryv1.EndpointPort{
		Name: ptr.To("web"), Port: ptr.To(int32(10000)), Protocol: ptr.To(corev1.ProtocolTCP),
	}))
	neighbor := cd.createNetworkNeighbor("", event, "default", client, nil, nil, nil, false)
	require.NotNil(t, neighbor)
	require.Equal(t, []int32{8080, 9090}, networkPortValues(neighbor.Ports))
	require.Empty(t, client.kubeClient.Actions())
	cd.emptyEvents()
	require.Nil(t, cd.servicePorts, "snapshots clear when their observations are emitted")
}
