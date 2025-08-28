package config

import (
	"os"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/exporters"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/rulecooldown"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	b := false
	tests := []struct {
		name    string
		path    string
		want    Config
		wantErr bool
	}{
		{
			name: "TestLoadConfig",
			path: "../../configuration",
			want: Config{
				EnableFullPathTracing:          true,
				EnableApplicationProfile:       true,
				EnableMalwareDetection:         true,
				EnableNetworkTracing:           true,
				EnableNodeProfile:              true,
				EnableHttpDetection:            true,
				EnableHostMalwareSensor:        false,
				EnableHostNetworkSensor:        false,
				EnableNetworkStreaming:         false,
				EnableEmbeddedSboms:            false,
				KubernetesMode:                 true,
				NetworkStreamingInterval:       2 * time.Minute,
				InitialDelay:                   2 * time.Minute,
				MaxSniffingTime:                6 * time.Hour,
				UpdateDataPeriod:               1 * time.Minute,
				NodeProfileInterval:            1 * time.Minute,
				MaxDelaySeconds:                30,
				MaxJitterPercentage:            5,
				MaxImageSize:                   5368709120,
				MaxSBOMSize:                    20971520,
				MaxTsProfileSize:               2 * 1024 * 1024,
				ProfilesCacheRefreshRate:       1 * time.Minute,
				ProcfsPidScanInterval:          5 * time.Second,
				EnablePrometheusExporter:       true,
				EnableRuntimeDetection:         true,
				EnableSeccomp:                  true,
				EnablePartialProfileGeneration: true,
				Exporters: exporters.ExportersConfig{
					SyslogExporter: "http://syslog.kubescape.svc.cluster.local:514",
					StdoutExporter: &b,
					AlertManagerExporterUrls: []string{
						"http://alertmanager.kubescape.svc.cluster.local:9093",
						"http://alertmanager.kubescape.svc.cluster.local:9095",
					},
					CsvRuleExporterPath:    "/rules",
					CsvMalwareExporterPath: "/malware",
					HTTPExporterConfig: &exporters.HTTPExporterConfig{
						URL: "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io",
					},
				},
				WorkerPoolSize:     3000,
				EventBatchSize:     15000,
				WorkerChannelSize:  750000,
				BlockEvents:        false,
				ProcfsScanInterval: 30 * time.Second,
				RuleCoolDown: rulecooldown.RuleCooldownConfig{
					CooldownDuration:   1 * time.Hour,
					CooldownAfterCount: 1,
					OnProfileFailure:   true,
					MaxSize:            10000,
				},
				OrderedEventQueue: containerwatcher.OrderedEventQueueConfig{
					Size:            100000,
					CollectionDelay: 50 * time.Millisecond,
				},
				ExitCleanup: processtreecreator.ExitCleanupConfig{
					MaxPendingExits: 1000,
					CleanupInterval: 30 * time.Second,
					CleanupDelay:    5 * time.Minute,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadConfig(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestIgnoreContainer tests the IgnoreContainer method of the Config struct.
func TestIgnoreContainer(t *testing.T) {
	config := Config{
		NamespaceName: "test-namespace",
		ExcludeLabels: map[string]string{
			"app.kubernetes.io/name": "test-app",
		},
		ExcludeNamespaces: []string{"excluded-namespace"},
	}

	tests := []struct {
		name     string
		ns       string
		podName  string
		labels   map[string]string
		envVar   string
		envValue string
		want     bool
	}{
		{
			name:    "Ignore pod in the same namespace",
			ns:      "test-namespace",
			podName: "some-pod",
			labels:  map[string]string{},
			want:    true,
		},
		{
			name:     "Ignore node-agent pod when MULTIPLY is true",
			ns:       "other-namespace",
			podName:  "node-agent-pod",
			labels:   map[string]string{},
			envVar:   "MULTIPLY",
			envValue: "true",
			want:     true,
		},
		{
			name:    "Ignore pod in excluded namespace",
			ns:      "excluded-namespace",
			podName: "some-pod",
			labels:  map[string]string{},
			want:    true,
		},
		{
			name:    "Ignore pod with excluded label",
			ns:      "other-namespace",
			podName: "some-pod",
			labels:  map[string]string{"app.kubernetes.io/name": "test-app"},
			want:    true,
		},
		{
			name:    "Do not ignore pod with no matching conditions",
			ns:      "other-namespace",
			podName: "some-pod",
			labels:  map[string]string{"app": "other-app"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				err := os.Setenv(tt.envVar, tt.envValue)
				require.NoError(t, err)
			}

			got := config.IgnoreContainer(tt.ns, tt.podName, tt.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSkipNamespace(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		namespace    string
		expectedSkip bool
	}{
		{
			name: "Namespace in IncludeNamespaces",
			config: Config{
				IncludeNamespaces: []string{"allowed-namespace"},
			},
			namespace:    "allowed-namespace",
			expectedSkip: false,
		},
		{
			name: "Namespace not in IncludeNamespaces",
			config: Config{
				IncludeNamespaces: []string{"allowed-namespace"},
			},
			namespace:    "other-namespace",
			expectedSkip: true,
		},
		{
			name: "Namespace in ExcludeNamespaces",
			config: Config{
				ExcludeNamespaces: []string{"excluded-namespace"},
			},
			namespace:    "excluded-namespace",
			expectedSkip: true,
		},
		{
			name: "Namespace not in ExcludeNamespaces",
			config: Config{
				ExcludeNamespaces: []string{"excluded-namespace"},
			},
			namespace:    "other-namespace",
			expectedSkip: false,
		},
		{
			name:         "No IncludeNamespaces or ExcludeNamespaces",
			config:       Config{},
			namespace:    "any-namespace",
			expectedSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip := tt.config.SkipNamespace(tt.namespace)
			assert.Equal(t, tt.expectedSkip, skip)
		})
	}
}
