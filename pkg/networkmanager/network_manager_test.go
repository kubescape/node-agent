package networkmanager

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher/dnsmanager"
	"testing"

	_ "embed"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

// this test is for development purposes
// func TestNetworkManager(t *testing.T) {
// 	cfg := config.Config{
// 		InitialDelay:     1 * time.Second,
// 		MaxSniffingTime:  5 * time.Minute,
// 		UpdateDataPeriod: 10 * time.Second,
// 	}
// 	ctx := context.TODO()
// 	k8sClient := k8sinterface.NewKubernetesApi()
// 	storageClient, err := storagev1.CreateStorageNoCache()
// 	assert.NoError(t, err)
// 	am := CreateNetworkManager(ctx, cfg, k8sClient, storageClient, "test-cluster")
// 	containers := []containercollection.Container{
// 		{
// 			K8s: containercollection.K8sMetadata{
// 				BasicK8sMetadata: types.BasicK8sMetadata{
// 					Namespace:     "default",
// 					PodName:       "nginx-deployment-fcc867f7-dgjrg",
// 					ContainerName: "nginx",
// 				},
// 			},
// 			Runtime: containercollection.RuntimeMetadata{
// 				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
// 					ContainerID: "docker://802c6c322d264557779fe785013a0dfa84eb658e7791aa36396da809fcb3329c",
// 				},
// 			},
// 		},
// 		{
// 			K8s: containercollection.K8sMetadata{
// 				BasicK8sMetadata: types.BasicK8sMetadata{
// 					Namespace:     "kube-system",
// 					PodName:       "fluentd-elasticsearch-hlsbx",
// 					ContainerName: "fluentd-elasticsearch",
// 				},
// 			},
// 			Runtime: containercollection.RuntimeMetadata{
// 				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
// 					ContainerID: "docker://50b40cad5db4165b712909453e1927d8baada94cdefa7c11b90cb775024d041d",
// 				},
// 			},
// 		},
// 	}
// 	for i := range containers {
// 		am.ContainerCallback(containercollection.PubSubEvent{
// 			Type:      containercollection.EventTypeAddContainer,
// 			Container: &containers[i],
// 		})
// 	}
// 	networkEvents := []*tracernetworktype.Event{
// 		{
// 			Port:      6666,
// 			PktType:   "HOST",
// 			Proto:     "tcp",
// 			PodLabels: map[string]string{"app5": "nginx5"},
// 			DstEndpoint: types.L3Endpoint{
// 				Namespace: "default",
// 				Name:      "nginx-deployment-cbdccf466-csh9c",
// 				Kind:      "pod",
// 				PodLabels: map[string]string{"app": "nginx2"},
// 				Addr:      "19.64.52.5",
// 			},
// 		},
// 		// {
// 		// 	Port:      8000,
// 		// 	PktType:   "HOST",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "app=nginx2",
// 		// 	Destination: Destination{
// 		// 		Namespace: "default",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindPod,
// 		// 		PodLabels: "app=nginx2",
// 		// 		IPAddress: "19.64.52.5",
// 		// 	},
// 		// },
// 		// {
// 		// 	Port:      80,
// 		// 	PktType:   "HOST",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "app=nginx",
// 		// 	Destination: Destination{
// 		// 		Namespace: "default",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindService,
// 		// 		PodLabels: "SERVICE=nginx2",
// 		// 		IPAddress: "19.64.52.4",
// 		// 	},
// 		// },
// 		// {
// 		// 	Port:      80,
// 		// 	PktType:   "HOST",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "app=nginx2",
// 		// 	Destination: Destination{
// 		// 		Namespace: "default",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindPod,
// 		// 		PodLabels: "app=nginx2",
// 		// 		IPAddress: "19.64.52.4",
// 		// 	},
// 		// },
// 		// {
// 		// 	Port:      3333,
// 		// 	PktType:   "OUTGOING",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "",
// 		// 	Destination: Destination{
// 		// 		Namespace: "",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindRaw,
// 		// 		PodLabels: "",
// 		// 		IPAddress: "19.64.52.4",
// 		// 	},
// 		// }, {
// 		// 	Port:      4444,
// 		// 	PktType:   "OUTGOING",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "",
// 		// 	Destination: Destination{
// 		// 		Namespace: "",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindRaw,
// 		// 		PodLabels: "",
// 		// 		IPAddress: "19.64.52.4",
// 		// 	},
// 		// }, {
// 		// 	Port:      4444,
// 		// 	PktType:   "OUTGOING",
// 		// 	Protocol:  "tcp",
// 		// 	PodLabels: "",
// 		// 	Destination: Destination{
// 		// 		Namespace: "",
// 		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
// 		// 		Kind:      EndpointKindRaw,
// 		// 		PodLabels: "",
// 		// 		IPAddress: "19.64.52.5",
// 		// 	},
// 		// },
// 	}
// 	time.Sleep(10 * time.Second)
// 	for i := range networkEvents {
// 		am.SaveNetworkEvent(containers[0].Runtime.ContainerID, containers[0].K8s.PodName, *networkEvents[i])
// 	}
// 	time.Sleep(150 * time.Second)
// }

func TestGenerateNeighborsIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    v1beta1.NetworkNeighbor
		expected string
	}{
		{
			name: "external",
			input: v1beta1.NetworkNeighbor{
				Type:              "external",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       nil,
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "a13ce4ca8de4083d05986cdc9874c5bc75870f93a89363acc36e12511ceae5d8",
		},
		{
			name: "external - different IP has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "external",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       nil,
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.3",
			},
			expected: "5e620390e1aa074ccca30576eb9e09db9254a07b1d6cef9b45d7f98a1f72c863",
		},
		{
			name: "internal",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port1", Protocol: "TCP"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "fd41d439d5de80f684d53dc9682ca335f93f6f754031d6e3624a9772b8010680",
		},
		{
			name: "internal - different ports has same identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "fd41d439d5de80f684d53dc9682ca335f93f6f754031d6e3624a9772b8010680",
		},
		{
			name: "internal - different pod labels has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "0848cb483e73375684bbc7333f64d74dfa13260fc9d9ff178cdead9b1f695944",
		},
		{
			name: "internal - different namespace labels has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "example.com",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				IPAddress:         "192.168.1.1",
			},
			expected: "d4e9bce7335a0eee24b725edb9de785fecfebad7bfc4f2ea4a49830925b745da",
		},
		{
			name: "internal - different dns has different identifier",
			input: v1beta1.NetworkNeighbor{
				Type:              "internal",
				DNS:               "another.co m",
				Ports:             []v1beta1.NetworkPort{{Name: "port2", Protocol: "udp"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app2": "nginx"}},
				NamespaceSelector: nil,
				IPAddress:         "192.168.1.1",
			},
			expected: "f3dd4abe5311abc6ab3768182af5a15cb96746dd82573a744e2132d9ac90f52d",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %+v", tc.input), func(t *testing.T) {
			result, err := generateNeighborsIdentifier(tc.input)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("in test: %s, Expected: %s, Got: %s", tc.name, tc.expected, result)
			}
		})
	}
}

func TestGeneratePortIdentifierFromEvent(t *testing.T) {
	testCases := []struct {
		input    NetworkEvent
		expected string
	}{
		{
			input: NetworkEvent{
				Port:     80,
				PktType:  "TCP",
				Protocol: "HTTP",
				Destination: Destination{
					Namespace: "namespace1",
					Name:      "name1",
					Kind:      EndpointKindPod,
					PodLabels: "label1=labelValue1,label2=labelValue2",
					IPAddress: "192.168.1.1",
				},
			},
			expected: "HTTP-80",
		},
		{
			input: NetworkEvent{
				Port:     333,
				PktType:  "TCP",
				Protocol: "UDP",
				Destination: Destination{
					Namespace: "namespace1",
					Name:      "name1",
					Kind:      EndpointKindPod,
					PodLabels: "label1=labelValue1,label2=labelValue2",
					IPAddress: "192.168.1.1",
				},
			},
			expected: "UDP-333",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %+v", tc.input), func(t *testing.T) {
			result := generatePortIdentifierFromEvent(tc.input)
			if result != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, result)
			}
		})
	}
}

type dnsResolverMock struct {
	addressToDomainMap *maps.SafeMap[string, string]
}

func (d *dnsResolverMock) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := d.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}

func TestGenerateNetworkNeighborsEntries(t *testing.T) {
	tests := []struct {
		name               string
		namespace          string
		networkEvents      []NetworkEvent
		expectedSpec       v1beta1.NetworkNeighborsSpec
		addressToDomainMap map[string]string
	}{
		{
			name:      "empty",
			namespace: "default",
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Egress:  []v1beta1.NetworkNeighbor{},
				Ingress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "pod from same namespace ingress - should not have namespace selector",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      80,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type:              "internal",
						DNS:               "",
						Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
				Egress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "pod from same namespace egress - should not have namespace selector",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      80,
					PktType:   "OUTGOING",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Egress: []v1beta1.NetworkNeighbor{
					{
						Type:              "internal",
						DNS:               "",
						Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
				Ingress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "pod from another namespace - should have namespace selector",
			namespace: "default",
			networkEvents: []NetworkEvent{
				{
					Port:      80,
					PktType:   "OUTGOING",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,pod-template-hash=test",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Egress: []v1beta1.NetworkNeighbor{
					{
						Type:              "internal",
						DNS:               "",
						Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
						IPAddress:         "",
						Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
					},
				},
				Ingress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "raw IP",
			namespace: "default",
			networkEvents: []NetworkEvent{
				{
					Port:     80,
					PktType:  "OUTGOING",
					Protocol: "UDP",
					Destination: Destination{
						Kind:      EndpointKindRaw,
						IPAddress: "143.54.53.21",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Egress: []v1beta1.NetworkNeighbor{
					{
						Type:       "external",
						DNS:        "",
						Ports:      []v1beta1.NetworkPort{{Name: "UDP-80", Protocol: "UDP", Port: ptr.To(int32(80))}},
						IPAddress:  "143.54.53.21",
						Identifier: "3bbd32606a8516f97e7e3c11b0e914744c56cd6b8a2cadf010dd5fc648285535",
					},
				},
				Ingress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "raw IP localhost - should be ignored",
			namespace: "default",
			networkEvents: []NetworkEvent{
				{
					Port:     80,
					PktType:  "OUTGOING",
					Protocol: "TCP",
					Destination: Destination{
						Kind:      EndpointKindRaw,
						IPAddress: "127.0.0.1",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Egress:  []v1beta1.NetworkNeighbor{},
				Ingress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "multiple events with different ports - ports are merged",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
				{
					Port:      2,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
				{
					Port:      3,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
				{
					Port:      3,
					PktType:   "OUTGOING",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type:              "internal",
						DNS:               "",
						Ports:             []v1beta1.NetworkPort{{Name: "TCP-1", Protocol: "TCP", Port: ptr.To(int32(1))}, {Name: "TCP-2", Protocol: "TCP", Port: ptr.To(int32(2))}, {Name: "TCP-3", Protocol: "TCP", Port: ptr.To(int32(3))}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
				Egress: []v1beta1.NetworkNeighbor{
					{
						Type:        "internal",
						DNS:         "",
						Ports:       []v1beta1.NetworkPort{{Name: "TCP-3", Protocol: "TCP", Port: ptr.To(int32(3))}},
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						IPAddress:   "",
						Identifier:  "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
			},
		},
		{
			name:      "multiple events - different ip labels are saved separately",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Kind:      EndpointKindRaw,
						IPAddress: "1.2.3.4",
					},
				},
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Kind:      EndpointKindRaw,
						IPAddress: "4.3.2.1",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type: "external",
						DNS:  "",
						Ports: []v1beta1.NetworkPort{
							{
								Name:     "TCP-1",
								Protocol: "TCP",
								Port:     ptr.To(int32(1)),
							},
						},
						IPAddress:  "1.2.3.4",
						Identifier: "24fe17e6c3ee75d94d0b3ab7ff3ffb8d60b8a108df505aae1bab241cc8f8ae91",
					},
					{
						Type: "external",
						DNS:  "",
						Ports: []v1beta1.NetworkPort{
							{
								Name:     "TCP-1",
								Protocol: "TCP",
								Port:     ptr.To(int32(1)),
							},
						},
						IPAddress:  "4.3.2.1",
						Identifier: "b94b02766fdf0694c9d2d03696f41c70e0df0784b4dc9e2ce2c9b1808bc8d273",
					},
				},
				Egress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "multiple events - different pod labels are saved separately",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Namespace: "kubescape",
						Name:      "nginx-deployment-cbdccf466-csh9c",
						Kind:      EndpointKindPod,
						PodLabels: "app=destination2,controller-revision-hash=hash",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type: "internal",
						DNS:  "",
						Ports: []v1beta1.NetworkPort{
							{
								Name:     "TCP-1",
								Protocol: "TCP",
								Port:     ptr.To(int32(1)),
							},
						},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination2"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "4c4c30e0f156db2ec7212a9ce68f17613a4a755325e647084ef9379f8eb6caaa",
					},
					{
						Type: "internal",
						DNS:  "",
						Ports: []v1beta1.NetworkPort{
							{
								Name:     "TCP-1",
								Protocol: "TCP",
								Port:     ptr.To(int32(1)),
							},
						},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
				Egress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "multiple events - different name are saved together",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						Namespace: "kubescape",
						Name:      "one",
						IPAddress: "1.2.3.4",
					},
				},
				{
					Port:      1,
					PktType:   "HOST",
					Protocol:  "TCP",
					PodLabels: "app=nginx",
					Destination: Destination{
						Kind:      EndpointKindPod,
						PodLabels: "app=destination,controller-revision-hash=hash",
						Namespace: "kubescape",
						Name:      "two",
						IPAddress: "1.2.3.4",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type:        "internal",
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						DNS:         "",
						Ports: []v1beta1.NetworkPort{
							{
								Name:     "TCP-1",
								Protocol: "TCP",
								Port:     ptr.To(int32(1)),
							},
						},
						IPAddress:  "",
						Identifier: "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
				Egress: []v1beta1.NetworkNeighbor{},
			},
		},
		{
			name:      "IP is resolved - DNS is enriched",
			namespace: "kubescape",
			networkEvents: []NetworkEvent{
				{
					Port:     1,
					PktType:  "HOST",
					Protocol: "TCP",
					Destination: Destination{
						Kind:      EndpointKindRaw,
						IPAddress: "1.2.3.4",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type: "external",
						DNS:  "domain.com",
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
				Egress: []v1beta1.NetworkNeighbor{},
			},
			addressToDomainMap: map[string]string{
				"1.2.3.4": "domain.com",
			},
		},
	}

	for _, tc := range tests {
		dnsResolver := dnsResolverMock{}
		dnsResolver.addressToDomainMap = &maps.SafeMap[string, string]{}

		for k, v := range tc.addressToDomainMap {
			dnsResolver.addressToDomainMap.Set(k, v)
		}

		am := CreateNetworkManager(context.TODO(), config.Config{}, nil, nil, "", &dnsResolver)
		networkEventsSet := mapset.NewSet[NetworkEvent]()
		for _, ne := range tc.networkEvents {
			networkEventsSet.Add(ne)
		}
		t.Run(fmt.Sprintf("Input: %+v", tc.networkEvents), func(t *testing.T) {
			result := am.generateNetworkNeighborsEntries(tc.namespace, networkEventsSet)

			assert.Equal(t, len(result.Ingress), len(tc.expectedSpec.Ingress), "Ingress IP address is not equal in test %s", tc.name)
			found := 0
			for _, ingress := range result.Ingress {
				for _, expectedIngress := range tc.expectedSpec.Ingress {
					if ingress.Identifier == expectedIngress.Identifier {
						assert.Equal(t, ingress.Type, expectedIngress.Type, "Ingress type is not equal in test %s", tc.name)
						assert.Equal(t, ingress.DNS, expectedIngress.DNS, "Ingress DNS is not equal in test %s", tc.name)
						assert.Equal(t, ingress.Ports, expectedIngress.Ports, "Ingress ports are not equal in test %s", tc.name)
						assert.Equal(t, ingress.PodSelector, expectedIngress.PodSelector, "Ingress pod selector is not equal in test %s", tc.name)
						assert.Equal(t, ingress.NamespaceSelector, expectedIngress.NamespaceSelector, "Ingress namespace selector is not equal in test %s", tc.name)
						assert.Equal(t, ingress.IPAddress, expectedIngress.IPAddress, "Ingress IP address is not equal in test %s", tc.name)

						assert.Equal(t, len(ingress.Ports), len(expectedIngress.Ports), "Ingress ports are not equal in test %s", tc.name)

						for _, port := range ingress.Ports {
							foundPort := false
							for _, expectedPort := range expectedIngress.Ports {
								if port.Name == expectedPort.Name && *port.Port == *expectedPort.Port && port.Protocol == expectedPort.Protocol {
									foundPort = true
									break
								}
							}
							assert.True(t, foundPort, "Port %+v not found in ingress %+v", port, ingress)
						}

						found++
					}
				}

			}
			assert.Equal(t, found, len(tc.expectedSpec.Ingress), "Ingress IP address is not equal in test %s", tc.name)

			assert.Equal(t, len(result.Egress), len(tc.expectedSpec.Egress), "Egress IP address is not equal in test %s", tc.name)
			found = 0
			for _, egress := range result.Egress {
				for _, expectedEgress := range tc.expectedSpec.Egress {
					if egress.Identifier == expectedEgress.Identifier {
						assert.Equal(t, egress.Type, expectedEgress.Type, "Egress type is not equal in test %s", tc.name)
						assert.Equal(t, egress.DNS, expectedEgress.DNS, "Egress DNS is not equal in test %s", tc.name)
						assert.Equal(t, egress.Ports, expectedEgress.Ports, "Egress ports are not equal in test %s", tc.name)
						assert.Equal(t, egress.PodSelector, expectedEgress.PodSelector, "Egress pod selector is not equal in test %s", tc.name)
						assert.Equal(t, egress.NamespaceSelector, expectedEgress.NamespaceSelector, "Egress namespace selector is not equal in test %s", tc.name)
						assert.Equal(t, egress.IPAddress, expectedEgress.IPAddress, "Egress IP address is not equal in test %s", tc.name)

						assert.Equal(t, len(egress.Ports), len(expectedEgress.Ports), "Egress ports are not equal in test %s", tc.name)

						for _, port := range egress.Ports {
							foundPort := false
							for _, expectedPort := range expectedEgress.Ports {
								if port.Name == expectedPort.Name && *port.Port == *expectedPort.Port && port.Protocol == expectedPort.Protocol {
									foundPort = true
									break
								}
							}
							assert.True(t, foundPort, "Port %+v not found in ingress %+v", port, egress)
						}

						found++
					}
				}
			}
			assert.Equal(t, found, len(tc.expectedSpec.Egress), "Egress IP address is not equal in test %s", tc.name)

		})
	}
}

func TestGetNamespaceMatchLabels(t *testing.T) {
	tests := []struct {
		name                 string
		destinationNamespace string
		sourceNamespace      string
		expected             map[string]string
	}{
		{
			name:                 "same namespace - should not have namespace selector",
			destinationNamespace: "default",
			sourceNamespace:      "default",
			expected:             nil,
		},
		{
			name:                 "different namespace - should have the destination namespace as selector",
			sourceNamespace:      "default",
			destinationNamespace: "kubescape",
			expected:             map[string]string{"kubernetes.io/metadata.name": "kubescape"},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := getNamespaceMatchLabels(tc.destinationNamespace, tc.sourceNamespace)
			assert.Equal(t, tc.expected, result)
		})
	}
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

	dnsResolver := dnsmanager.CreateDNSManagerMock()
	am := CreateNetworkManager(context.TODO(), config.Config{}, nil, nil, "test", dnsResolver)

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := am.isValidEvent(tc.event)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGeneratePortIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		protocol string
		expected string
	}{
		{
			name:     "http",
			port:     80,
			protocol: "TCP",
			expected: "TCP-80",
		},
		{
			name:     "udp",
			port:     333,
			protocol: "UDP",
			expected: "UDP-333",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %s", tc.name), func(t *testing.T) {
			result := generatePortIdentifier(tc.protocol, tc.port)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// saveNeighborEntry(networkEvent NetworkEvent, neighborEntry v1beta1.NetworkNeighbor, egressIdentifiersMap map[string]v1beta1.NetworkNeighbor, ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor)
func TestSaveNeighborEntry(t *testing.T) {
	tests := []struct {
		name                  string
		networkEvent          NetworkEvent
		neighborEntry         v1beta1.NetworkNeighbor
		egressIdentifiersMap  map[string]v1beta1.NetworkNeighbor
		ingressIdentifiersMap map[string]v1beta1.NetworkNeighbor
		expectedEgressMap     map[string]v1beta1.NetworkNeighbor
		expectedIngressMap    map[string]v1beta1.NetworkNeighbor
	}{
		{
			name: "egress event is saved",
			networkEvent: NetworkEvent{
				Port:     80,
				PktType:  "OUTGOING",
				Protocol: "TCP",
			},
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			egressIdentifiersMap: map[string]v1beta1.NetworkNeighbor{},
			expectedEgressMap: map[string]v1beta1.NetworkNeighbor{
				"9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9": {
					Type: "internal",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9",
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
					},
				},
			},
		},
		{
			name: "ingress event is saved",
			networkEvent: NetworkEvent{
				Port:     80,
				PktType:  "HOST",
				Protocol: "TCP",
			},
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			ingressIdentifiersMap: map[string]v1beta1.NetworkNeighbor{},
			expectedIngressMap: map[string]v1beta1.NetworkNeighbor{
				"9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9": {
					Type: "internal",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9",
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
					},
				},
			},
		},
		{
			name: "existing data in map - map is updated",
			networkEvent: NetworkEvent{
				Port:     80,
				PktType:  "HOST",
				Protocol: "TCP",
			},
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			ingressIdentifiersMap: map[string]v1beta1.NetworkNeighbor{
				"710652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9": {
					Type: "internal",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "710652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9",
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "test"},
					},
				},
			},
			expectedIngressMap: map[string]v1beta1.NetworkNeighbor{
				"710652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9": {
					Type: "internal",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "710652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9",
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"test": "test"},
					},
				},
				"9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9": {
					Type: "internal",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "9f0652b5eef6b239f6a7c83778e56ab1ac3a2ad700ca7097f1cb59b1502ecee9",
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
					},
				},
			},
		},
		{
			name: "external event is saved",
			networkEvent: NetworkEvent{
				Port:     80,
				PktType:  "OUTGOING",
				Protocol: "TCP",
			},
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "external",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
			},
			egressIdentifiersMap: map[string]v1beta1.NetworkNeighbor{},
			expectedEgressMap: map[string]v1beta1.NetworkNeighbor{
				"1db1cf596388ac2f0d5eecbe6bcc9b57199beaa7d87e53a049ae18744dd62045": {
					Type: "external",
					Ports: []v1beta1.NetworkPort{
						{
							Name:     "TCP-80",
							Protocol: "TCP",
							Port:     ptr.To(int32(80)),
						},
					},
					Identifier: "1db1cf596388ac2f0d5eecbe6bcc9b57199beaa7d87e53a049ae18744dd62045",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %+v", tc.networkEvent), func(t *testing.T) {
			saveNeighborEntry(tc.networkEvent, tc.neighborEntry, tc.egressIdentifiersMap, tc.ingressIdentifiersMap)
			assert.Equal(t, tc.expectedEgressMap, tc.egressIdentifiersMap)
			assert.Equal(t, tc.expectedIngressMap, tc.ingressIdentifiersMap)
		})
	}

}

// addToMap(identifiersMap map[string]v1beta1.NetworkNeighbor, identifier string, portIdentifier string, neighborEntry v1beta1.NetworkNeighbor)
func TestAddToMap(t *testing.T) {
	tests := []struct {
		name           string
		identifiersMap map[string]v1beta1.NetworkNeighbor
		identifier     string
		portIdentifier string
		neighborEntry  v1beta1.NetworkNeighbor
		expectedMap    map[string]v1beta1.NetworkNeighbor
	}{
		{
			name:           "new identifier is added",
			identifiersMap: map[string]v1beta1.NetworkNeighbor{},
			identifier:     "identifier",
			portIdentifier: "portIdentifier",
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			expectedMap: map[string]v1beta1.NetworkNeighbor{
				"identifier": {
					Type:              "internal",
					DNS:               "",
					Identifier:        "identifier",
					Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
		},
		{
			name: "same identifier with new ports - ports are appended",
			identifiersMap: map[string]v1beta1.NetworkNeighbor{
				"identifier": {
					Type:              "internal",
					DNS:               "",
					Identifier:        "identifier",
					Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
			identifier:     "identifier",
			portIdentifier: "TCP-50",
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-50", Protocol: "TCP", Port: ptr.To(int32(50))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			expectedMap: map[string]v1beta1.NetworkNeighbor{
				"identifier": {
					Type:       "internal",
					DNS:        "",
					Identifier: "identifier",
					Ports: []v1beta1.NetworkPort{
						{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
						{Name: "TCP-50", Protocol: "TCP", Port: ptr.To(int32(50))},
					},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
		},
		{
			name: "different identifier - identifiers are appended",
			identifiersMap: map[string]v1beta1.NetworkNeighbor{
				"identifier1": {
					Type:              "internal",
					DNS:               "",
					Identifier:        "identifier1",
					Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
			identifier:     "identifier2",
			portIdentifier: "TCP-80",
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			expectedMap: map[string]v1beta1.NetworkNeighbor{
				"identifier1": {
					Type:       "internal",
					DNS:        "",
					Identifier: "identifier1",
					Ports: []v1beta1.NetworkPort{
						{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
					},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
				"identifier2": {
					Type:       "internal",
					DNS:        "",
					Identifier: "identifier2",
					Ports: []v1beta1.NetworkPort{
						{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
					},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
		},
		{
			name: "same identifier with same ports - nothing happens",
			identifiersMap: map[string]v1beta1.NetworkNeighbor{
				"identifier": {
					Type:              "internal",
					DNS:               "",
					Identifier:        "identifier",
					Ports:             []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
			identifier:     "identifier",
			portIdentifier: "TCP-80",
			neighborEntry: v1beta1.NetworkNeighbor{
				Type:       "internal",
				DNS:        "",
				Identifier: "",
				Ports:      []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"},
				},
			},
			expectedMap: map[string]v1beta1.NetworkNeighbor{
				"identifier": {
					Type:       "internal",
					DNS:        "",
					Identifier: "identifier",
					Ports: []v1beta1.NetworkPort{
						{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))},
					},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kubescape"}},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Input: %+v", tc.name), func(t *testing.T) {
			addToMap(tc.identifiersMap, tc.identifier, tc.portIdentifier, tc.neighborEntry)
			assert.Equal(t, tc.expectedMap, tc.identifiersMap)
		})
	}
}
