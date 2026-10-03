package utils

import (
	"testing"

	celtypes "github.com/google/cel-go/common/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/picatz/xcel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNetworkCelEvent struct {
	CelEventImpl
	endpoint igtypes.L4Endpoint
}

func (m *mockNetworkCelEvent) GetDstEndpoint() igtypes.L4Endpoint {
	return m.endpoint
}

func TestCelFields_DstNamespaceAndDstPodLabels(t *testing.T) {
	dstNsField, ok := CelFields["dstNamespace"]
	require.True(t, ok)
	dstLabelsField, ok := CelFields["dstPodLabels"]
	require.True(t, ok)

	// 1. Pod peer with labels
	event := &mockNetworkCelEvent{
		endpoint: igtypes.L4Endpoint{
			L3Endpoint: igtypes.L3Endpoint{
				Namespace: "prod",
				Name:      "api-pod",
				Kind:      igtypes.EndpointKindPod,
				PodLabels: map[string]string{"app": "api", "tier": "backend"},
			},
		},
	}
	wrapped, _ := xcel.NewObject[CelEvent](event)

	val, err := dstNsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, celtypes.String("prod"), val)

	val, err = dstLabelsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api", "tier": "backend"}, val)

	// 2. Service peer with metadata labels resolves through ServicePeerLabels hook
	SetServicePeerLabels(func(ns, name string) map[string]string {
		if ns == "prod" && name == "api-service" {
			return map[string]string{"app": "api-resolved"}
		}
		return nil
	})
	defer SetServicePeerLabels(nil)

	svcEvent := &mockNetworkCelEvent{
		endpoint: igtypes.L4Endpoint{
			L3Endpoint: igtypes.L3Endpoint{
				Namespace: "prod",
				Name:      "api-service",
				Kind:      igtypes.EndpointKindService,
				PodLabels: map[string]string{"app.kubernetes.io/name": "service-metadata-only"},
			},
		},
	}
	svcWrapped, _ := xcel.NewObject[CelEvent](svcEvent)

	val, err = dstLabelsField.GetFrom(svcWrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "api-resolved"}, val)

	// 3. Fallback with no resolver yields empty map, not nil
	SetServicePeerLabels(nil)
	val, err = dstLabelsField.GetFrom(svcWrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, val)
}
