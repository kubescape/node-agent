package v2

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestCreateNetworkManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 1 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	dnsManager := &dnsmanager.DNSManagerMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	watchedContainers := &maps.SafeMap[string, *utils.WatchedContainerData]{}
	am := CreateNetworkManager(ctx, cfg, "cluster", k8sClient, storageClient, dnsManager, mapset.NewSet[string](), k8sObjectCacheMock, watchedContainers)
	// prepare container
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
			},
		},
	}
	// report network event
	go am.ReportNetworkEvent("ns/pod/cont", tracernetworktype.Event{
		Port:      80,
		PktType:   "HOST",
		Proto:     "TCP",
		PodLabels: map[string]string{"app": "nginx"},
		DstEndpoint: types.L3Endpoint{
			Namespace: "kubescape",
			Name:      "nginx-deployment-cbdccf466-csh9c",
			Kind:      "pod",
			Addr:      "1.2.3.4",
			PodLabels: map[string]string{"app": "destination", "controller-revision-hash": "hash"},
		},
	})
	// report container started (race condition with reports)
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// let it run for a while
	time.Sleep(15 * time.Second)
	// more events
	go am.ReportNetworkEvent("ns/pod/cont", tracernetworktype.Event{
		Port:      443,
		PktType:   "OUTGOING",
		Proto:     "TCP",
		PodLabels: map[string]string{"app": "nginx"},
		DstEndpoint: types.L3Endpoint{
			Namespace: "kubescape",
			Name:      "nginx-deployment-cbdccf466-csh9c",
			Kind:      "pod",
			Addr:      "1.2.3.4",
			PodLabels: map[string]string{"app": "destination", "controller-revision-hash": "hash"},
		},
	})
	// sleep more
	time.Sleep(2 * time.Second)
	// report container stopped
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	// let it stop
	time.Sleep(2 * time.Second)
	// verify generated CRDs
	assert.Equal(t, 2, len(storageClient.NetworkNeighborhoods))
	// check the first neighborhood
	assert.Equal(t, v1beta1.NetworkNeighbor{
		Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
		Type:              "internal",
		Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
		PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
	}, storageClient.NetworkNeighborhoods[0].Spec.Containers[1].Ingress[0])
	assert.Equal(t, 0, len(storageClient.NetworkNeighborhoods[0].Spec.Containers[1].Egress))
	// check the second neighborhood - this is a patch for execs and opens
	assert.Equal(t, v1beta1.NetworkNeighbor{
		Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
		Type:              "internal",
		Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
		PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
	}, storageClient.NetworkNeighborhoods[1].Spec.Containers[1].Ingress[0])
	assert.Equal(t, v1beta1.NetworkNeighbor{
		Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
		Type:              "internal",
		Ports:             []v1beta1.NetworkPort{{Name: "TCP-443", Protocol: "TCP", Port: ptr.To(int32(443))}},
		PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
	}, storageClient.NetworkNeighborhoods[1].Spec.Containers[1].Egress[0])
}

func TestIsValidEvent(t *testing.T) {
	tests := []struct {
		name     string
		event    tracernetworktype.Event
		expected bool
	}{
		{
			name: "invalid pkt type",
			event: tracernetworktype.Event{
				PktType: "INVALID",
			},
			expected: false,
		},
		{
			name: "pkt to itself",
			event: tracernetworktype.Event{
				PktType:   "HOST",
				PodHostIP: "1.2.3.4",
				DstEndpoint: types.L3Endpoint{
					Addr: "1.2.3.4",
				},
			},
			expected: false,
		},
		{
			name: "host network",
			event: tracernetworktype.Event{
				Event: types.Event{
					CommonData: types.CommonData{
						K8s: types.K8sMetadata{
							HostNetwork: true,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "localhost IP",
			event: tracernetworktype.Event{
				DstEndpoint: types.L3Endpoint{
					Addr: "169.254.169.254",
				},
			},
			expected: false,
		},
		{
			name: "valid event",
			event: tracernetworktype.Event{
				Port:      80,
				PktType:   "HOST",
				Proto:     "tcp",
				PodLabels: map[string]string{"app": "nginx"},
				DstEndpoint: types.L3Endpoint{
					Namespace: "default",
					Name:      "nginx-deployment-cbdccf466-csh9c",
					Kind:      "pod",
					PodLabels: map[string]string{"app": "nginx2"},
					Addr:      "19.64.52.5",
				},
			},
			expected: true,
		},
	}

	am := &NetworkManager{}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := am.isValidEvent(tc.event)
			assert.Equal(t, tc.expected, result)
		})
	}
}

type dnsResolverMock struct{}

func (d *dnsResolverMock) ResolveIPAddress(ipAddr string) (string, bool) {
	if ipAddr == "1.2.3.4" {
		return "domain.com", true
	}
	return "", false
}

func (d *dnsResolverMock) ResolveContainerProcessToCloudServices(containerId string, pid uint32) mapset.Set[string] {
	return nil
}

func TestNetworkManager_createNetworkNeighbor(t *testing.T) {
	tests := []struct {
		name         string
		namespace    string
		networkEvent networkmanager.NetworkEvent
		want         *v1beta1.NetworkNeighbor
	}{
		{
			name:      "empty",
			namespace: "default",
			want: &v1beta1.NetworkNeighbor{
				Type:       "external",
				Ports:      []v1beta1.NetworkPort{{Name: "-0", Protocol: "", Port: ptr.To(int32(0))}},
				Identifier: "1db1cf596388ac2f0d5eecbe6bcc9b57199beaa7d87e53a049ae18744dd62045",
			},
		},
		{
			name:      "pod from same namespace egress - should not have namespace selector",
			namespace: "kubescape",
			networkEvent: networkmanager.NetworkEvent{
				Port:      80,
				PktType:   "OUTGOING",
				Protocol:  "TCP",
				PodLabels: "app=nginx",
				Destination: networkmanager.Destination{
					Namespace: "kubescape",
					Name:      "nginx-deployment-cbdccf466-csh9c",
					Kind:      networkmanager.EndpointKindPod,
					PodLabels: "app=destination,controller-revision-hash=hash",
					IPAddress: "",
				},
			},
			want: &v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "",
				Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
				NamespaceSelector: nil,
				IPAddress:         "",
				Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
			},
		},
		{
			name:      "pod from another namespace - should have namespace selector",
			namespace: "default",
			networkEvent: networkmanager.NetworkEvent{
				Port:      80,
				PktType:   "OUTGOING",
				Protocol:  "TCP",
				PodLabels: "app=nginx",
				Destination: networkmanager.Destination{
					Namespace: "kubescape",
					Name:      "nginx-deployment-cbdccf466-csh9c",
					Kind:      networkmanager.EndpointKindPod,
					PodLabels: "app=destination,pod-template-hash=test",
					IPAddress: "",
				},
			},
			want: &v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "",
				Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				IPAddress:         "",
				Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
			},
		},
		{
			name:      "raw IP",
			namespace: "default",
			networkEvent: networkmanager.NetworkEvent{
				Port:     80,
				PktType:  "OUTGOING",
				Protocol: "UDP",
				Destination: networkmanager.Destination{
					Kind:      networkmanager.EndpointKindRaw,
					IPAddress: "143.54.53.21",
				},
			},
			want: &v1beta1.NetworkNeighbor{
				Type:       "external",
				DNS:        "",
				Ports:      []v1beta1.NetworkPort{{Name: "UDP-80", Protocol: "UDP", Port: ptr.To(int32(80))}},
				IPAddress:  "143.54.53.21",
				Identifier: "3bbd32606a8516f97e7e3c11b0e914744c56cd6b8a2cadf010dd5fc648285535",
			},
		},
		{
			name:      "raw IP localhost - should be ignored",
			namespace: "default",
			networkEvent: networkmanager.NetworkEvent{
				Port:     80,
				PktType:  "OUTGOING",
				Protocol: "TCP",
				Destination: networkmanager.Destination{
					Kind:      networkmanager.EndpointKindRaw,
					IPAddress: "127.0.0.1",
				},
			},
			want: nil,
		},
		{
			name:      "IP is resolved - DNS is enriched",
			namespace: "kubescape",
			networkEvent: networkmanager.NetworkEvent{
				Port:     1,
				PktType:  "HOST",
				Protocol: "TCP",
				Destination: networkmanager.Destination{
					Kind:      networkmanager.EndpointKindRaw,
					IPAddress: "1.2.3.4",
				},
			},
			want: &v1beta1.NetworkNeighbor{
				Type:     "external",
				DNS:      "domain.com",
				DNSNames: []string{"domain.com"},
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "TCP-1",
						Protocol: "TCP",
						Port:     ptr.To(int32(1)),
					},
				},
				IPAddress:  "1.2.3.4",
				Identifier: "12f9a2d88f8ca830047d7b6324e9ded773a803e42b50a01a36009fc447fc6fb0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am := &NetworkManager{
				dnsResolverClient: &dnsResolverMock{},
			}
			got := am.createNetworkNeighbor(tt.networkEvent, tt.namespace)
			assert.Equal(t, tt.want, got)
		})
	}
}
