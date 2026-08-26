package containerprofilemanager

import (
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type fakeServiceClient struct {
	namespace, name string
	selector        map[string]interface{}
	labels          map[string]interface{}
}

func (f *fakeServiceClient) GetWorkload(namespace, _, name string) (k8sinterface.IWorkload, error) {
	meta := map[string]interface{}{"name": name, "namespace": namespace}
	if f.labels != nil {
		meta["labels"] = f.labels
	}
	spec := map[string]interface{}{}
	if f.selector != nil {
		spec["selector"] = f.selector
	}
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   meta,
		"spec":       spec,
	}), nil
}

func (f *fakeServiceClient) CalculateWorkloadParentRecursive(w k8sinterface.IWorkload) (string, string, error) {
	return w.GetKind(), w.GetName(), nil
}
func (f *fakeServiceClient) GetKubernetesClient() kubernetes.Interface { return nil }
func (f *fakeServiceClient) GetDynamicClient() dynamic.Interface       { return nil }

// A service neighbor records its stable ClusterIP so detection matches the peer
// by address (the learned selector alone misses on CNIs that keep the pre-DNAT
// ClusterIP on the wire, since IG stamps the service's metadata labels while the
// learned selector holds the pod selector), and a selectorless service is kept.
func TestCreateNetworkNeighbor_ServiceRecordsClusterIP(t *testing.T) {
	const clusterIP = "10.43.12.34"
	cd := &containerData{watchedContainerData: &objectcache.WatchedContainerData{Namespace: "default"}}
	ev := NetworkEvent{
		Port:     80,
		Protocol: "tcp",
		PktType:  utils.OutgoingPktType,
		Destination: Destination{
			Kind:      EndpointKindService,
			Namespace: "default",
			Name:      "nginx",
			IPAddress: clusterIP,
		},
	}

	withSel := &fakeServiceClient{selector: map[string]interface{}{"app": "nginx"}}
	n := cd.createNetworkNeighbor(ev, "default", withSel, nil)
	require.NotNil(t, n)
	assert.Equal(t, clusterIP, n.IPAddress, "a service neighbor must record its stable ClusterIP")
	require.NotNil(t, n.PodSelector, "a service with a selector keeps its pod selector")
	assert.Equal(t, "nginx", n.PodSelector.MatchLabels["app"])

	noSel := &fakeServiceClient{}
	n2 := cd.createNetworkNeighbor(ev, "default", noSel, nil)
	require.NotNil(t, n2, "a selectorless service must not be dropped — the ClusterIP identifies it")
	assert.Equal(t, clusterIP, n2.IPAddress)
	assert.Nil(t, n2.PodSelector, "no selector to learn when the service defines none")
}
