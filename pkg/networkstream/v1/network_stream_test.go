package networkstream

import (
	"context"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
)

func TestNewNetworkStream(t *testing.T) {
	tests := []struct {
		name            string
		cfg             config.Config
		expectedTimeout time.Duration
	}{
		{
			name: "with http exporter config and custom timeout",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						TimeoutSeconds: 10,
					},
				},
			},
			expectedTimeout: 10 * time.Second,
		},
		{
			name: "with http exporter config but no timeout",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						TimeoutSeconds: 0,
					},
				},
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
		{
			name: "without http exporter config",
			cfg: config.Config{
				KubernetesMode: false,
				Exporters: exporters.ExportersConfig{
					HTTPExporterConfig: nil,
				},
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
		{
			name: "kubernetes mode disabled",
			cfg: config.Config{
				KubernetesMode: false,
			},
			expectedTimeout: timeoutDefaultSeconds * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			nodeName := "test-node"
			eventsChannel := make(chan apitypes.NetworkStream, 1)

			ns, err := NewNetworkStream(
				ctx,
				tt.cfg,
				nil, // k8sObjectCache
				nil, // dnsResolver
				nodeName,
				eventsChannel,
				true, // dnsSupport
				nil,  // processTreeManager
			)

			if err != nil {
				t.Fatalf("NewNetworkStream() error = %v", err)
			}

			if ns == nil {
				t.Fatal("NewNetworkStream() returned nil")
			}

			// Check HTTP client timeout
			if ns.httpClient.Timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout %v, got %v", tt.expectedTimeout, ns.httpClient.Timeout)
			}

			// Check that networkEventsStorage is initialized
			if ns.networkEventsStorage.Entities == nil {
				t.Error("networkEventsStorage.Entities should not be nil")
			}

			// Check that host entity is created
			hostEntity, exists := ns.networkEventsStorage.Entities[nodeName]
			if !exists {
				t.Errorf("Host entity for node %s should exist", nodeName)
			}

			if hostEntity.Kind != apitypes.NetworkStreamEntityKindHost {
				t.Errorf("Expected host entity kind %v, got %v", apitypes.NetworkStreamEntityKindHost, hostEntity.Kind)
			}

			if hostEntity.Inbound == nil || hostEntity.Outbound == nil {
				t.Error("Host entity Inbound and Outbound maps should be initialized")
			}

			// Check other fields are set correctly
			if ns.nodeName != nodeName {
				t.Errorf("Expected nodeName %s, got %s", nodeName, ns.nodeName)
			}

			if ns.dnsSupport != true {
				t.Error("Expected dnsSupport to be true")
			}

			if ns.eventsNotificationChannel != eventsChannel {
				t.Error("eventsNotificationChannel not set correctly")
			}
		})
	}
}
