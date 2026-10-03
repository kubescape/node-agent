package rulemanager

import (
	"errors"
	"testing"

	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/picatz/xcel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockServiceK8sClient struct {
	k8sclient.K8sClientMock
	services map[string]k8sinterface.IWorkload
}

func (m *mockServiceK8sClient) GetWorkload(namespace, kind, name string) (k8sinterface.IWorkload, error) {
	if kind != "Service" {
		return m.K8sClientMock.GetWorkload(namespace, kind, name)
	}
	key := namespace + "/" + name
	if svc, ok := m.services[key]; ok {
		return svc, nil
	}
	return nil, errors.New("service not found")
}

func TestInitServicePeerLabelResolver(t *testing.T) {
	defer utils.SetServicePeerLabels(nil)

	svcWorkload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "my-svc",
			"namespace": "prod",
			"labels": map[string]any{
				"helm.sh/chart": "my-chart-1.0.0",
			},
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app":  "backend",
				"tier": "api",
			},
		},
	})

	k8sDefaultSvc := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "kubernetes",
			"namespace": "default",
			"labels": map[string]any{
				"component": "apiserver",
				"provider":  "kubernetes",
			},
		},
		"spec": map[string]any{},
	})

	mockClient := &mockServiceK8sClient{
		services: map[string]k8sinterface.IWorkload{
			"prod/my-svc":          svcWorkload,
			"default/kubernetes":   k8sDefaultSvc,
		},
	}

	// 1. Initialize resolver with mock client
	InitServicePeerLabelResolver(mockClient)

	// Verify standard service returns selector labels, not metadata labels
	labels := utils.ServicePeerLabels("prod", "my-svc")
	assert.Equal(t, map[string]string{"app": "backend", "tier": "api"}, labels)

	// Verify default/kubernetes service returns metadata labels
	k8sLabels := utils.ServicePeerLabels("default", "kubernetes")
	assert.Equal(t, map[string]string{"component": "apiserver", "provider": "kubernetes"}, k8sLabels)

	// Verify non-existent service returns nil
	notFoundLabels := utils.ServicePeerLabels("prod", "unknown-svc")
	assert.Nil(t, notFoundLabels)

	// 2. Verify integration with CEL dstPodLabels getter
	dstLabelsField, ok := utils.CelFields["dstPodLabels"]
	require.True(t, ok)

	event := &mockNetworkEvent{
		endpoint: igtypes.L4Endpoint{
			L3Endpoint: igtypes.L3Endpoint{
				Namespace: "prod",
				Name:      "my-svc",
				Kind:      igtypes.EndpointKindService,
				PodLabels: map[string]string{"helm.sh/chart": "my-chart-1.0.0"}, // metadata label from kubeipresolver
			},
		},
	}
	wrapped, _ := xcel.NewObject[utils.CelEvent](event)

	val, err := dstLabelsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "backend", "tier": "api"}, val)

	// 3. Clear resolver on nil client
	InitServicePeerLabelResolver(nil)
	assert.Nil(t, utils.ServicePeerLabels("prod", "my-svc"))

	// Verify fallback to empty map when resolver is nil
	val, err = dstLabelsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, val)
}

type mockNetworkEvent struct {
	utils.CelEventImpl
	endpoint igtypes.L4Endpoint
}

func (m *mockNetworkEvent) GetDstEndpoint() igtypes.L4Endpoint {
	return m.endpoint
}
