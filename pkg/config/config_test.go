package config

import (
	"os"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/exporters"
	hostfimsensor "github.com/kubescape/node-agent/pkg/hostfimsensor/v1"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/rulecooldown"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	b := false
	fimStdout := true
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
				EnableFullPathTracing:          false,
				EnableApplicationProfile:       true,
				EnableMalwareDetection:         false,
				EnableNetworkTracing:           false,
				EnableNodeProfile:              false,
				EnableHttpDetection:            false,
				EnableHostMalwareSensor:        false,
				EnableHostNetworkSensor:        false,
				EnableFIM:                      true,
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
				EnablePrometheusExporter:       false,
				EnableRuntimeDetection:         false,
				EnableSeccomp:                  false,
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
				DNSCacheSize: 50000,
				FIM: FIMConfig{
					Directories: []FIMDirectoryConfig{
						{
							Path:     "/etc",
							OnCreate: true,
							OnChange: true,
							OnRemove: true,
							OnRename: true,
							OnChmod:  true,
							OnMove:   true,
						},
						{
							Path:     "/usr/bin",
							OnCreate: true,
							OnChange: true,
							OnRemove: true,
							OnRename: true,
							OnChmod:  true,
							OnMove:   true,
						},
						{
							Path:     "/usr/sbin",
							OnCreate: true,
							OnChange: true,
							OnRemove: true,
							OnRename: true,
							OnChmod:  true,
							OnMove:   true,
						},
						{
							Path:     "/boot",
							OnCreate: true,
							OnChange: true,
							OnRemove: true,
							OnRename: true,
							OnChmod:  true,
							OnMove:   true,
						},
					},
					BackendConfig: hostfimsensor.HostFimBackendConfig{
						BackendType: hostfimsensor.FimBackendPeriodic,
					},
					BatchConfig: hostfimsensor.HostFimBatchConfig{
						MaxBatchSize: 1000,
						BatchTimeout: time.Minute,
					},
					DedupConfig: hostfimsensor.HostFimDedupConfig{
						DedupEnabled:    true,
						DedupTimeWindow: 5 * time.Minute,
						MaxCacheSize:    10000,
					},
					PeriodicConfig: &hostfimsensor.HostFimPeriodicConfig{
						ScanInterval:     30 * time.Second,
						MaxScanDepth:     10,
						MaxSnapshotNodes: 100000,
						IncludeHidden:    false,
						ExcludePatterns:  []string{"*.tmp", "*.log", "*.cache", "/proc/*", "/sys/*", "/dev/*", "/run/*"},
						MaxFileSize:      100 * 1024 * 1024,
						FollowSymlinks:   false,
					},
					Exporters: FIMExportersConfig{
						StdoutExporter: &fimStdout,
					},
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
		ExcludeLabels: map[string][]string{
			"app.kubernetes.io/name": {"test-app"},
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

func TestFIMConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	configContent := `{
		"fimEnabled": true,
		"fim": {
			"directories": [
				{
					"path": "/etc",
					"onCreate": true,
					"onChange": true,
					"onRemove": true,
					"onRename": false,
					"onChmod": true,
					"onMove": false
				},
				{
					"path": "/var/log",
					"onCreate": true,
					"onChange": true,
					"onRemove": true,
					"onRename": false,
					"onChmod": false,
					"onMove": false
				}
			],
			"batchConfig": {
				"maxBatchSize": 500,
				"batchTimeout": "30s"
			},
			"dedupConfig": {
				"dedupEnabled": true,
				"dedupTimeWindow": "2m",
				"maxCacheSize": 2000
			},
			"exporters": {
				"stdoutExporter": true,
				"alertManagerExporterUrls": ["http://alertmanager:9093"]
			}
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config using viper directly to avoid loading the default config
	viper.Reset()
	viper.AddConfigPath(tempDir)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	// Set FIM defaults
	viper.SetDefault("fim::enabled", false)
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	err = viper.ReadInConfig()
	require.NoError(t, err)

	var cfg Config
	err = viper.Unmarshal(&cfg)
	require.NoError(t, err)

	// Test FIM configuration
	assert.True(t, cfg.EnableFIM)
	assert.Len(t, cfg.FIM.Directories, 2)

	// Test first directory
	dir1 := cfg.FIM.Directories[0]
	assert.Equal(t, "/etc", dir1.Path)
	assert.True(t, dir1.OnCreate)
	assert.True(t, dir1.OnChange)
	assert.True(t, dir1.OnRemove)
	assert.False(t, dir1.OnRename)
	assert.True(t, dir1.OnChmod)
	assert.False(t, dir1.OnMove)

	// Test second directory
	dir2 := cfg.FIM.Directories[1]
	assert.Equal(t, "/var/log", dir2.Path)
	assert.True(t, dir2.OnCreate)
	assert.True(t, dir2.OnChange)
	assert.True(t, dir2.OnRemove)
	assert.False(t, dir2.OnRename)
	assert.False(t, dir2.OnChmod)
	assert.False(t, dir2.OnMove)

	// Test batch configuration
	assert.Equal(t, 500, cfg.FIM.BatchConfig.MaxBatchSize)
	assert.Equal(t, 30*time.Second, cfg.FIM.BatchConfig.BatchTimeout)

	// Test dedup configuration
	assert.True(t, cfg.FIM.DedupConfig.DedupEnabled)
	assert.Equal(t, 2*time.Minute, cfg.FIM.DedupConfig.DedupTimeWindow)
	assert.Equal(t, 2000, cfg.FIM.DedupConfig.MaxCacheSize)

	// Test exporters configuration
	assert.True(t, *cfg.FIM.Exporters.StdoutExporter)
	assert.Len(t, cfg.FIM.Exporters.AlertManagerExporterUrls, 1)
	assert.Equal(t, "http://alertmanager:9093", cfg.FIM.Exporters.AlertManagerExporterUrls[0])
}

func TestFIMConfigDefaults(t *testing.T) {
	// Create a temporary config file with minimal FIM config
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	configContent := `{
		"fimEnabled": true,
		"fim": {
			"directories": [
				{
					"path": "/etc",
					"onCreate": true,
					"onChange": true,
					"onRemove": true
				}
			]
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config using viper directly
	viper.Reset()
	viper.AddConfigPath(tempDir)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	// Set FIM defaults
	viper.SetDefault("fim::enabled", false)
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	err = viper.ReadInConfig()
	require.NoError(t, err)

	var cfg Config
	err = viper.Unmarshal(&cfg)
	require.NoError(t, err)

	// Test default values
	assert.True(t, cfg.EnableFIM)
	assert.Len(t, cfg.FIM.Directories, 1)

	// Test default batch configuration
	assert.Equal(t, 1000, cfg.FIM.BatchConfig.MaxBatchSize)
	assert.Equal(t, time.Minute, cfg.FIM.BatchConfig.BatchTimeout)

	// Test default dedup configuration
	assert.True(t, cfg.FIM.DedupConfig.DedupEnabled)
	assert.Equal(t, 5*time.Minute, cfg.FIM.DedupConfig.DedupTimeWindow)
	assert.Equal(t, 1000, cfg.FIM.DedupConfig.MaxCacheSize)

	// Test default exporters configuration
	assert.False(t, *cfg.FIM.Exporters.StdoutExporter)
}

func TestFIMConfigDisabled(t *testing.T) {
	// Create a temporary config file with FIM disabled
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	configContent := `{
		"fim": {
			"enabled": false
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config using viper directly
	viper.Reset()
	viper.AddConfigPath(tempDir)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	// Set FIM defaults
	viper.SetDefault("fim::enabled", false)
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	err = viper.ReadInConfig()
	require.NoError(t, err)

	var cfg Config
	err = viper.Unmarshal(&cfg)
	require.NoError(t, err)

	// Test that FIM is disabled
	assert.False(t, cfg.EnableFIM)
}

func TestGetFIMPathConfigs(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	configContent := `{
		"fim": {
			"enabled": true,
			"directories": [
				{
					"path": "/etc",
					"onCreate": true,
					"onChange": true,
					"onRemove": true,
					"onRename": false,
					"onChmod": true,
					"onMove": false
				}
			]
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config using viper directly
	viper.Reset()
	viper.AddConfigPath(tempDir)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	// Set FIM defaults
	viper.SetDefault("fim::enabled", false)
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	err = viper.ReadInConfig()
	require.NoError(t, err)

	var cfg Config
	err = viper.Unmarshal(&cfg)
	require.NoError(t, err)

	// Test GetFIMPathConfigs
	pathConfigs := cfg.FIM.GetFIMPathConfigs()
	assert.Len(t, pathConfigs, 1)

	pathConfig := pathConfigs[0]
	assert.Equal(t, "/etc", pathConfig.Path)
	assert.True(t, pathConfig.OnCreate)
	assert.True(t, pathConfig.OnChange)
	assert.True(t, pathConfig.OnRemove)
	assert.False(t, pathConfig.OnRename)
	assert.True(t, pathConfig.OnChmod)
	assert.False(t, pathConfig.OnMove)
}

func TestGetFIMExportersConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"

	configContent := `{
		"fim": {
			"enabled": true,
			"directories": [
				{
					"path": "/etc",
					"onCreate": true,
					"onChange": true,
					"onRemove": true
				}
			],
			"exporters": {
				"stdoutExporter": true,
				"syslogExporterURL": "udp://syslog:514",
				"alertManagerExporterUrls": ["http://alertmanager:9093"]
			}
		}
	}`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config using viper directly
	viper.Reset()
	viper.AddConfigPath(tempDir)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	// Set FIM defaults
	viper.SetDefault("fim::enabled", false)
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	err = viper.ReadInConfig()
	require.NoError(t, err)

	var cfg Config
	err = viper.Unmarshal(&cfg)
	require.NoError(t, err)

	// Test GetFIMExportersConfig
	exportersConfig := cfg.FIM.GetFIMExportersConfig()
	assert.True(t, *exportersConfig.StdoutExporter)
	assert.Equal(t, "udp://syslog:514", exportersConfig.SyslogExporter)
	assert.Len(t, exportersConfig.AlertManagerExporterUrls, 1)
	assert.Equal(t, "http://alertmanager:9093", exportersConfig.AlertManagerExporterUrls[0])
}
