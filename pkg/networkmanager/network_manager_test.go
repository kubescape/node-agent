package networkmanager

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	storagev1 "node-agent/pkg/storage/v1"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestNetworkManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 10 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient, err := storagev1.CreateStorageNoCache()
	assert.NoError(t, err)

	am := CreateNetworkManager(ctx, cfg, k8sClient, storageClient, "test-cluster")

	containers := []containercollection.Container{
		{
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "default",
					PodName:       "nginx-deployment-fcc867f7-dgjrg",
					ContainerName: "nginx",
				},
			},
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: "docker://802c6c322d264557779fe785013a0dfa84eb658e7791aa36396da809fcb3329c",
				},
			},
		},
		{
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "kube-system",
					PodName:       "fluentd-elasticsearch-hlsbx",
					ContainerName: "fluentd-elasticsearch",
				},
			},
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: "docker://50b40cad5db4165b712909453e1927d8baada94cdefa7c11b90cb775024d041d",
				},
			},
		},
	}

	for i := range containers {
		am.ContainerCallback(containercollection.PubSubEvent{
			Type:      containercollection.EventTypeAddContainer,
			Container: &containers[i],
		})
	}

	networkEvents := []*NetworkEvent{
		{
			Port:      80,
			PktType:   "HOST",
			Protocol:  "tcp",
			PodLabels: "app=nginx2",
			Destination: Destination{
				Namespace: "default",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindPod,
				PodLabels: "app=nginx2",
				IPAddress: "19.64.52.5",
			},
		},
		// {
		// 	Port:      8000,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx2",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindPod,
		// 		PodLabels: "app=nginx2",
		// 		IPAddress: "19.64.52.5",
		// 	},
		// },
		// {
		// 	Port:      80,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindService,
		// 		PodLabels: "SERVICE=nginx2",
		// 		IPAddress: "19.64.52.4",
		// 	},
		// },
		// {
		// 	Port:      80,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx2",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindPod,
		// 		PodLabels: "app=nginx2",
		// 		IPAddress: "19.64.52.4",
		// 	},
		// },
		{
			Port:      3333,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.4",
			},
		}, {
			Port:      4444,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.4",
			},
		}, {
			Port:      4444,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.5",
			},
		},
	}

	time.Sleep(10 * time.Second)
	for i := range networkEvents {
		am.SaveNetworkEvent(containers[0].Runtime.ContainerID, containers[0].K8s.PodName, networkEvents[i])
	}
	time.Sleep(150 * time.Second)

}

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

func TestGeneratePortIdentifier(t *testing.T) {
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
			result := generatePortIdentifier(tc.input)
			if result != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, result)
			}
		})
	}
}

func TestGenerateNetworkNeighborsEntries(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		networkEvents []NetworkEvent
		expectedSpec  v1beta1.NetworkNeighborsSpec
	}{
		{
			name:         "empty",
			namespace:    "default",
			expectedSpec: v1beta1.NetworkNeighborsSpec{},
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
			},
		},
		{
			name:      "service from same namespace - should not have namespace selector",
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
						Kind:      EndpointKindService,
						PodLabels: "app=destination",
						IPAddress: "",
					},
				},
			},
			expectedSpec: v1beta1.NetworkNeighborsSpec{
				Ingress: []v1beta1.NetworkNeighbor{
					{
						Type:        "internal",
						DNS:         "",
						Ports:       []v1beta1.NetworkPort{{Name: "TCP-80", Protocol: "TCP", Port: ptr.To(int32(80))}},
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						IPAddress:   "",
						Identifier:  "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
					},
				},
			},
		},
		{
			name:      "service from another namespace - should have namespace selector",
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
						Kind:      EndpointKindService,
						PodLabels: "app=destination",
						IPAddress: "1.2.3.4",
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
						Identifier:        "c86024d63c2bfddde96a258c3005e963e06fb9d8ee941a6de3003d6eae5dd7cc",
					},
				},
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
			expectedSpec: v1beta1.NetworkNeighborsSpec{},
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
			name:      "multiple events with same ports - only one port is saved",
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
						PodLabels: "app=destination,controller-revision-hash=hash",
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
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
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
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "0d13d659ca4ba62f02f78781a15e1bfb4f88b29761d06c1b90cfa8834d9845c7",
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
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "destination2"}},
						NamespaceSelector: nil,
						IPAddress:         "",
						Identifier:        "4c4c30e0f156db2ec7212a9ce68f17613a4a755325e647084ef9379f8eb6caaa",
					},
				},
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
			},
		},
	}

	for _, tc := range tests {
		networkEventsSet := mapset.NewSet[NetworkEvent]()
		for _, ne := range tc.networkEvents {
			networkEventsSet.Add(ne)
		}
		t.Run(fmt.Sprintf("Input: %+v", tc.networkEvents), func(t *testing.T) {
			result := generateNetworkNeighborsEntries(tc.namespace, networkEventsSet)

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
