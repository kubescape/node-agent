package containerprofilemanager

import (
	"fmt"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/networkpolicy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

type servicePortTestClient struct {
	service    k8sinterface.IWorkload
	endpoints  k8sinterface.IWorkload
	kubeClient *fake.Clientset
	getErr     error
}

var _ k8sclient.K8sClientInterface = (*servicePortTestClient)(nil)

func (c *servicePortTestClient) GetWorkload(_, kind, _ string) (k8sinterface.IWorkload, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	switch kind {
	case "Service":
		return c.service, nil
	case "Endpoints":
		return c.endpoints, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}

func (c *servicePortTestClient) CalculateWorkloadParentRecursive(workload k8sinterface.IWorkload) (string, string, error) {
	return workload.GetKind(), workload.GetName(), nil
}

func (c *servicePortTestClient) GetKubernetesClient() kubernetes.Interface {
	return c.kubeClient
}

func (c *servicePortTestClient) GetDynamicClient() dynamic.Interface {
	return nil
}

func newServiceWorkload(name string, selector map[string]interface{}, ports ...map[string]interface{}) k8sinterface.IWorkload {
	portEntries := make([]interface{}, 0, len(ports))
	for _, port := range ports {
		portEntries = append(portEntries, port)
	}
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"selector": selector,
			"ports":    portEntries,
		},
	})
}

func newEndpointsWorkload(name string, ports ...map[string]interface{}) k8sinterface.IWorkload {
	portEntries := make([]interface{}, 0, len(ports))
	for _, port := range ports {
		portEntries = append(portEntries, port)
	}
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Endpoints",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
		"subsets": []interface{}{
			map[string]interface{}{
				"ports": portEntries,
			},
		},
	})
}

func newEndpointSlice(name, serviceName string, ports ...discoveryv1.EndpointPort) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: serviceName,
			},
		},
		Ports: ports,
	}
}

func serviceNetworkEvent(port uint16, protocol string) NetworkEvent {
	return NetworkEvent{
		Port:     port,
		Protocol: protocol,
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindService,
			Namespace: "default",
			Name:      "api",
		},
	}
}

func TestCreateNetworkNeighbor_ServiceTargetPortMatrix(t *testing.T) {
	tests := []struct {
		name          string
		service       k8sinterface.IWorkload
		endpoints     k8sinterface.IWorkload
		endpointSlice []*discoveryv1.EndpointSlice
		event         NetworkEvent
		wantPorts     []int32
	}{
		{
			name: "numeric remap",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 80, "targetPort": 8080, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{8080},
		},
		{
			name: "unchanged when port equals targetPort",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 8080, "targetPort": 8080, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(8080, "tcp"),
			wantPorts: []int32{8080},
		},
		{
			name: "omitted targetPort defaults to service port",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 80, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{80},
		},
		{
			name: "udp remap",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 53, "targetPort": 5353, "protocol": "UDP",
			}),
			event:     serviceNetworkEvent(53, "udp"),
			wantPorts: []int32{5353},
		},
		{
			name: "multi-port service selects matching service port",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"},
				map[string]interface{}{"port": 80, "targetPort": 8080, "protocol": "TCP"},
				map[string]interface{}{"port": 443, "targetPort": 8443, "protocol": "TCP"},
			),
			event:     serviceNetworkEvent(443, "tcp"),
			wantPorts: []int32{8443},
		},
		{
			name: "protocol mismatch keeps observed port",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 80, "targetPort": 8080, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(80, "udp"),
			wantPorts: []int32{80},
		},
		{
			name: "unknown observed port falls back",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"port": 80, "targetPort": 8080, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(9999, "tcp"),
			wantPorts: []int32{9999},
		},
		{
			name: "malformed service falls back safely",
			service: workloadinterface.NewWorkloadObj(map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata":   map[string]interface{}{"name": "api", "namespace": "default"},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{"app": "api"},
					"ports":    "invalid",
				},
			}),
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{80},
		},
		{
			name: "named targetPort resolves via endpointslice on service port name",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
			}),
			endpointSlice: []*discoveryv1.EndpointSlice{
				newEndpointSlice("api-a", "api", discoveryv1.EndpointPort{
					Name:     ptr.To("web"),
					Port:     ptr.To(int32(8080)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				}),
			},
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{8080},
		},
		{
			name: "heterogeneous named targetPort collects all endpoint ports",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
			}),
			endpointSlice: []*discoveryv1.EndpointSlice{
				newEndpointSlice("api-a", "api", discoveryv1.EndpointPort{
					Name:     ptr.To("web"),
					Port:     ptr.To(int32(8080)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				}),
				newEndpointSlice("api-b", "api", discoveryv1.EndpointPort{
					Name:     ptr.To("web"),
					Port:     ptr.To(int32(9090)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				}),
			},
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{8080, 9090},
		},
		{
			name: "endpoints fallback when no endpointslice",
			service: newServiceWorkload("api", map[string]interface{}{"app": "api"}, map[string]interface{}{
				"name": "web", "port": 80, "targetPort": "http", "protocol": "TCP",
			}),
			endpoints: newEndpointsWorkload("api", map[string]interface{}{
				"name": "web", "port": 8080, "protocol": "TCP",
			}),
			event:     serviceNetworkEvent(80, "tcp"),
			wantPorts: []int32{8080},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objects := make([]runtime.Object, 0, len(tc.endpointSlice))
			for _, slice := range tc.endpointSlice {
				objects = append(objects, slice)
			}
			client := &servicePortTestClient{
				service:    tc.service,
				endpoints:  tc.endpoints,
				kubeClient: fake.NewClientset(objects...),
			}

			cd := &containerData{}
			neighbor := cd.createNetworkNeighbor("", tc.event, "default", client, nil)
			require.NotNil(t, neighbor)
			require.Equal(t, map[string]string{"app": "api"}, neighbor.PodSelector.MatchLabels)
			require.Equal(t, tc.wantPorts, networkPortValues(neighbor.Ports))

			if tc.name == "numeric remap" {
				require.Equal(t, int32(8080), *neighbor.Ports[0].Port)
				require.NotEqual(t, int32(80), *neighbor.Ports[0].Port)
				require.Equal(t, "tcp-8080", neighbor.Ports[0].Name)
			}
		})
	}
}

func TestCreateNetworkNeighbor_NonServiceDestinationsUnchanged(t *testing.T) {
	cd := &containerData{}

	podEvent := NetworkEvent{
		Port:     8080,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindPod,
			Namespace: "default",
			Name:      "web",
		},
	}
	podEvent.SetDestinationPodLabels(map[string]string{"app": "web"})
	podNeighbor := cd.createNetworkNeighbor("", podEvent, "default", nil, nil)
	require.NotNil(t, podNeighbor)
	require.Equal(t, []int32{8080}, networkPortValues(podNeighbor.Ports))

	rawEvent := NetworkEvent{
		Port:     443,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			IPAddress: "93.184.216.34",
		},
	}
	rawNeighbor := cd.createNetworkNeighbor("", rawEvent, "default", nil, nil)
	require.NotNil(t, rawNeighbor)
	require.Equal(t, []int32{443}, networkPortValues(rawNeighbor.Ports))
}

func TestGenerateNetworkPolicy_ServiceTargetPortRoundTrip(t *testing.T) {
	service := newServiceWorkload("api", map[string]interface{}{"app.kubernetes.io/name": "api"}, map[string]interface{}{
		"port": 80, "targetPort": 8080, "protocol": "TCP",
	})
	client := &servicePortTestClient{
		service:    service,
		kubeClient: fake.NewClientset(),
	}

	cd := &containerData{}
	event := serviceNetworkEvent(80, "tcp")
	neighbor := cd.createNetworkNeighbor("", event, "default", client, nil)
	require.NotNil(t, neighbor)

	egressPorts := make([]softwarecomposition.NetworkPort, 0, len(neighbor.Ports))
	for _, port := range neighbor.Ports {
		egressPorts = append(egressPorts, softwarecomposition.NetworkPort{
			Protocol: softwarecomposition.Protocol(port.Protocol),
			Port:     port.Port,
			Name:     port.Name,
		})
	}

	cp := &softwarecomposition.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment-client",
			Namespace: "default",
			Labels: map[string]string{
				helpersv1.RelatedKindMetadataKey: "Deployment",
				helpersv1.RelatedNameMetadataKey: "client",
			},
			Annotations: map[string]string{
				helpersv1.StatusMetadataKey: helpersv1.Completed,
			},
		},
		Spec: softwarecomposition.ContainerProfileSpec{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "client"},
			},
			Egress: []softwarecomposition.NetworkNeighbor{{
				PodSelector: neighbor.PodSelector,
				Ports:       egressPorts,
				Type:        softwarecomposition.CommunicationType(neighbor.Type),
			}},
		},
	}

	gnp, err := networkpolicy.GenerateNetworkPolicy(cp, softwarecomposition.NewKnownServersFinderImpl(nil), metav1.Now())
	require.NoError(t, err)
	require.NotEmpty(t, gnp.Spec.Spec.Egress)

	var found8080 bool
	for _, rule := range gnp.Spec.Spec.Egress {
		for _, port := range rule.Ports {
			if port.Port != nil && *port.Port == 8080 {
				found8080 = true
			}
			if port.Port != nil {
				assert.NotEqual(t, int32(80), *port.Port)
			}
		}
	}
	assert.True(t, found8080)
}

func TestResolveServiceEnforcementPorts_Unit(t *testing.T) {
	t.Run("dedupe and sort", func(t *testing.T) {
		require.Equal(t, []uint16{8080, 9090}, dedupeSortPorts([]uint16{9090, 8080, 9090}))
	})
}
