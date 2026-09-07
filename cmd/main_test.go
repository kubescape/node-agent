package main

import (
	"errors"
	"testing"

	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	servicediscoveryv3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestResolveSbomFailureReportReceiverURL(t *testing.T) {
	tests := []struct {
		name          string
		cfg           config.Config
		apiURL        string
		services      schema.IBackendServices
		loadErr       error
		wantURL       string
		wantAPIURL    string
		wantLoadCalls int
	}{
		{
			name:          "disabled by default",
			cfg:           config.Config{},
			apiURL:        "configured.example.com",
			wantLoadCalls: 0,
		},
		{
			name: "failure reporting disabled",
			cfg: config.Config{
				EnableSbomGeneration: true,
			},
			apiURL:        "configured.example.com",
			wantLoadCalls: 0,
		},
		{
			name: "SBOM generation disabled",
			cfg: config.Config{
				EnableSbomFailureReporting: true,
			},
			apiURL:        "configured.example.com",
			wantLoadCalls: 0,
		},
		{
			name: "enabled with configured API URL",
			cfg: config.Config{
				EnableSbomGeneration:       true,
				EnableSbomFailureReporting: true,
			},
			apiURL:        "configured.example.com",
			services:      servicesWithReportReceiverURL("https://receiver.example.com"),
			wantURL:       "https://receiver.example.com",
			wantAPIURL:    "configured.example.com",
			wantLoadCalls: 1,
		},
		{
			name: "enabled with default API URL",
			cfg: config.Config{
				EnableSbomGeneration:       true,
				EnableSbomFailureReporting: true,
			},
			services:      servicesWithReportReceiverURL("https://receiver.example.com"),
			wantURL:       "https://receiver.example.com",
			wantAPIURL:    defaultAPIURL,
			wantLoadCalls: 1,
		},
		{
			name: "service discovery failure",
			cfg: config.Config{
				EnableSbomGeneration:       true,
				EnableSbomFailureReporting: true,
			},
			loadErr:       errors.New("service discovery failed"),
			wantAPIURL:    defaultAPIURL,
			wantLoadCalls: 1,
		},
		{
			name: "nil services",
			cfg: config.Config{
				EnableSbomGeneration:       true,
				EnableSbomFailureReporting: true,
			},
			wantAPIURL:    defaultAPIURL,
			wantLoadCalls: 1,
		},
		{
			name: "empty report receiver URL",
			cfg: config.Config{
				EnableSbomGeneration:       true,
				EnableSbomFailureReporting: true,
			},
			services:      servicesWithReportReceiverURL(""),
			wantAPIURL:    defaultAPIURL,
			wantLoadCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadCalls := 0
			var gotAPIURL string
			loader := func(apiURL string) (schema.IBackendServices, error) {
				loadCalls++
				gotAPIURL = apiURL
				return tt.services, tt.loadErr
			}

			gotURL := resolveSbomFailureReportReceiverURL(tt.cfg, tt.apiURL, loader)

			assert.Equal(t, tt.wantURL, gotURL)
			assert.Equal(t, tt.wantLoadCalls, loadCalls)
			assert.Equal(t, tt.wantAPIURL, gotAPIURL)
		})
	}
}

func servicesWithReportReceiverURL(reportReceiverURL string) schema.IBackendServices {
	services := &servicediscoveryv3.ServicesV3{}
	services.SetReportReceiverHttpUrl(reportReceiverURL)
	return services
}
