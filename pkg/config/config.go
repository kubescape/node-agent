package config

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hostfimsensor/v1"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/rulecooldown"
	"github.com/spf13/viper"
)

const NodeNameEnvVar = "NODE_NAME"
const PodNameEnvVar = "POD_NAME"
const NamespaceEnvVar = "NAMESPACE_NAME"

type Config struct {
	Exporters                      exporters.ExportersConfig                `mapstructure:"exporters"`
	InitialDelay                   time.Duration                            `mapstructure:"initialDelay"`
	MaxSniffingTime                time.Duration                            `mapstructure:"maxSniffingTimePerContainer"`
	UpdateDataPeriod               time.Duration                            `mapstructure:"updateDataPeriod"`
	MaxDelaySeconds                int                                      `mapstructure:"maxDelaySeconds"`
	MaxJitterPercentage            int                                      `mapstructure:"maxJitterPercentage"`
	MaxImageSize                   int64                                    `mapstructure:"maxImageSize"`
	MaxSBOMSize                    int                                      `mapstructure:"maxSBOMSize"`
	MaxTsProfileSize               int64                                    `mapstructure:"maxTsProfileSize"`
	EnableFullPathTracing          bool                                     `mapstructure:"fullPathTracingEnabled"`
	EnableApplicationProfile       bool                                     `mapstructure:"applicationProfileServiceEnabled"`
	EnableMalwareDetection         bool                                     `mapstructure:"malwareDetectionEnabled"`
	EnablePrometheusExporter       bool                                     `mapstructure:"prometheusExporterEnabled"`
	EnableRuntimeDetection         bool                                     `mapstructure:"runtimeDetectionEnabled"`
	EnableHttpDetection            bool                                     `mapstructure:"httpDetectionEnabled"`
	EnableNetworkTracing           bool                                     `mapstructure:"networkServiceEnabled"`
	EnableNetworkStreaming         bool                                     `mapstructure:"networkStreamingEnabled"`
	EnableNodeProfile              bool                                     `mapstructure:"nodeProfileServiceEnabled"`
	EnableHostMalwareSensor        bool                                     `mapstructure:"hostMalwareSensorEnabled"`
	EnableHostNetworkSensor        bool                                     `mapstructure:"hostNetworkSensorEnabled"`
	EnableFIM                      bool                                     `mapstructure:"fimEnabled"`
	NodeProfileInterval            time.Duration                            `mapstructure:"nodeProfileInterval"`
	EnableSeccomp                  bool                                     `mapstructure:"seccompServiceEnabled"`
	ExcludeLabels                  map[string][]string                      `mapstructure:"excludeLabels"`
	ExcludeNamespaces              []string                                 `mapstructure:"excludeNamespaces"`
	IncludeNamespaces              []string                                 `mapstructure:"includeNamespaces"`
	EnableSbomGeneration           bool                                     `mapstructure:"sbomGenerationEnabled"`
	EnableEmbeddedSboms            bool                                     `mapstructure:"enableEmbeddedSBOMs"`
	NamespaceName                  string                                   `mapstructure:"namespaceName"`
	NodeName                       string                                   `mapstructure:"nodeName"`
	PodName                        string                                   `mapstructure:"podName"`
	KubernetesMode                 bool                                     `mapstructure:"kubernetesMode"`
	NetworkStreamingInterval       time.Duration                            `mapstructure:"networkStreamingInterval"`
	WorkerPoolSize                 int                                      `mapstructure:"workerPoolSize"`
	WorkerChannelSize              int                                      `mapstructure:"workerChannelSize"`
	BlockEvents                    bool                                     `mapstructure:"blockEvents"`
	EventBatchSize                 int                                      `mapstructure:"eventBatchSize"`
	TestMode                       bool                                     `mapstructure:"testMode"`
	ExcludeJsonPaths               []string                                 `mapstructure:"excludeJsonPaths"`
	ProfilesCacheRefreshRate       time.Duration                            `mapstructure:"profilesCacheRefreshRate"`
	RuleCoolDown                   rulecooldown.RuleCooldownConfig          `mapstructure:"ruleCooldown"`
	EnablePartialProfileGeneration bool                                     `mapstructure:"partialProfileGenerationEnabled"`
	ProcfsScanInterval             time.Duration                            `mapstructure:"procfsScanInterval"`
	ProcfsPidScanInterval          time.Duration                            `mapstructure:"procfsPidScanInterval"`
	OrderedEventQueue              containerwatcher.OrderedEventQueueConfig `mapstructure:"orderedEventQueue"`
	ExitCleanup                    processtreecreator.ExitCleanupConfig     `mapstructure:"exitCleanup"`
	DNSCacheSize                   int                                      `mapstructure:"dnsCacheSize"`
	DCapSys                        bool                                     `mapstructure:"dCapSys"`
	DDns                           bool                                     `mapstructure:"dDns"`
	DExec                          bool                                     `mapstructure:"dExec"`
	DExit                          bool                                     `mapstructure:"dExit"`
	DFork                          bool                                     `mapstructure:"dFork"`
	DHardlink                      bool                                     `mapstructure:"dHardlink"`
	DHttp                          bool                                     `mapstructure:"dHttp"`
	DIouring                       bool                                     `mapstructure:"dIouring"`
	DNetwork                       bool                                     `mapstructure:"dNetwork"`
	DOpen                          bool                                     `mapstructure:"dOpen"`
	DPtrace                        bool                                     `mapstructure:"dPtrace"`
	DRandomx                       bool                                     `mapstructure:"dRandomx"`
	DSeccomp                       bool                                     `mapstructure:"dSeccomp"`
	DSsh                           bool                                     `mapstructure:"dSsh"`
	DSymlink                       bool                                     `mapstructure:"dSymlink"`
	DTop                           bool                                     `mapstructure:"dTop"`
	FIM                            FIMConfig                                `mapstructure:"fim"`
}

// FIMConfig defines the configuration for File Integrity Monitoring
type FIMConfig struct {
	Directories    []FIMDirectoryConfig                 `mapstructure:"directories"`
	BackendConfig  hostfimsensor.HostFimBackendConfig   `mapstructure:"backendConfig"`
	BatchConfig    hostfimsensor.HostFimBatchConfig     `mapstructure:"batchConfig"`
	DedupConfig    hostfimsensor.HostFimDedupConfig     `mapstructure:"dedupConfig"`
	PeriodicConfig *hostfimsensor.HostFimPeriodicConfig `mapstructure:"periodicConfig"`
	Exporters      FIMExportersConfig                   `mapstructure:"exporters"`
}

// FIMDirectoryConfig defines configuration for a directory to monitor
type FIMDirectoryConfig struct {
	Path     string `mapstructure:"path"`
	OnCreate bool   `mapstructure:"onCreate"`
	OnChange bool   `mapstructure:"onChange"`
	OnRemove bool   `mapstructure:"onRemove"`
	OnRename bool   `mapstructure:"onRename"`
	OnChmod  bool   `mapstructure:"onChmod"`
	OnMove   bool   `mapstructure:"onMove"`
}

// FIMExportersConfig defines which exporters to use for FIM events
type FIMExportersConfig struct {
	StdoutExporter           *bool                         `mapstructure:"stdoutExporter"`
	HTTPExporterConfig       *exporters.HTTPExporterConfig `mapstructure:"httpExporterConfig"`
	SyslogExporter           string                        `mapstructure:"syslogExporterURL"`
	AlertManagerExporterUrls []string                      `mapstructure:"alertManagerExporterUrls"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.SetOptions(viper.KeyDelimiter("::"))

	viper.SetDefault("fullPathTracingEnabled", true)
	viper.SetDefault("initialDelay", 2*time.Minute)
	viper.SetDefault("nodeProfileInterval", 10*time.Minute)
	viper.SetDefault("maxDelaySeconds", 30)
	viper.SetDefault("maxJitterPercentage", 5)
	viper.SetDefault("maxImageSize", 5*1024*1024*1024)
	viper.SetDefault("maxSBOMSize", 20*1024*1024)
	viper.SetDefault("maxTsProfileSize", 2*1024*1024)
	viper.SetDefault("namespaceName", os.Getenv(NamespaceEnvVar))
	viper.SetDefault("nodeName", os.Getenv(NodeNameEnvVar))
	viper.SetDefault("podName", os.Getenv(PodNameEnvVar))
	viper.SetDefault("hostMalwareSensorEnabled", false)
	viper.SetDefault("hostNetworkSensorEnabled", false)
	viper.SetDefault("fimEnabled", false)
	viper.SetDefault("networkStreamingEnabled", false)
	viper.SetDefault("kubernetesMode", true)
	viper.SetDefault("networkStreamingInterval", 2*time.Minute)
	viper.SetDefault("workerPoolSize", 3000)
	viper.SetDefault("eventBatchSize", 15000)
	viper.SetDefault("testMode", false)
	viper.SetDefault("enableEmbeddedSBOMs", false)
	viper.SetDefault("profilesCacheRefreshRate", 1*time.Minute)
	viper.SetDefault("ruleCooldown::ruleCooldownDuration", 1*time.Hour)
	viper.SetDefault("ruleCooldown::ruleCooldownAfterCount", 1)
	viper.SetDefault("ruleCooldown::ruleCooldownOnProfileFailure", true)
	viper.SetDefault("ruleCooldown::ruleCooldownMaxSize", 10000)
	viper.SetDefault("partialProfileGenerationEnabled", true)
	viper.SetDefault("procfsScanInterval", 30*time.Second)
	viper.SetDefault("procfsPidScanInterval", 5*time.Second)
	viper.SetDefault("orderedEventQueue::size", 100000)
	viper.SetDefault("orderedEventQueue::collectionDelay", 50*time.Millisecond)
	viper.SetDefault("exitCleanup::maxPendingExits", 1000)
	viper.SetDefault("exitCleanup::cleanupInterval", 30*time.Second)
	viper.SetDefault("exitCleanup::cleanupDelay", 5*time.Minute)
	viper.SetDefault("workerChannelSize", 750000)
	viper.SetDefault("blockEvents", false)
	viper.SetDefault("dnsCacheSize", 50000)
	// FIM defaults
	viper.SetDefault("fim::backendConfig::backendType", "fanotify") // This will be parsed as a string and converted to FimBackendType
	viper.SetDefault("fim::batchConfig::maxBatchSize", 1000)
	viper.SetDefault("fim::batchConfig::batchTimeout", "1m")
	viper.SetDefault("fim::dedupConfig::dedupEnabled", true)
	viper.SetDefault("fim::dedupConfig::dedupTimeWindow", "5m")
	viper.SetDefault("fim::dedupConfig::maxCacheSize", 1000)
	viper.SetDefault("fim::periodicConfig::scanInterval", 5*time.Minute)
	viper.SetDefault("fim::periodicConfig::maxScanDepth", 10)
	viper.SetDefault("fim::periodicConfig::maxSnapshotNodes", 100000)
	viper.SetDefault("fim::periodicConfig::includeHidden", false)
	viper.SetDefault("fim::periodicConfig::maxFileSize", int64(100*1024*1024))
	viper.SetDefault("fim::periodicConfig::followSymlinks", false)
	viper.SetDefault("fim::exporters::stdoutExporter", false)

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}

func (c *Config) IgnoreContainer(ns, podName string, labels map[string]string) bool {
	// do not trace any of our pods
	if ns == c.NamespaceName {
		return true
	}
	// do not trace the node-agent pods if MULTIPLY is set
	if m := os.Getenv("MULTIPLY"); m == "true" {
		if strings.HasPrefix(podName, "node-agent") {
			return true
		}
	}
	// check if config excludes the namespace
	if c.SkipNamespace(ns) {
		return true
	}
	// check if config excludes the pod labels
	for k, values := range c.ExcludeLabels {
		if labelValue, ok := labels[k]; ok {
			for _, v := range values {
				if strings.EqualFold(labelValue, v) {
					return true
				}
			}
		}
	}
	return false
}

func (c *Config) SkipNamespace(ns string) bool {
	if includeNamespaces := c.IncludeNamespaces; len(includeNamespaces) > 0 {
		if !slices.Contains(includeNamespaces, ns) {
			// skip ns not in IncludeNamespaces
			return true
		}
	} else if excludeNamespaces := c.ExcludeNamespaces; len(excludeNamespaces) > 0 {
		if slices.Contains(excludeNamespaces, ns) {
			// skip ns in ExcludeNamespaces
			return true
		}
	}
	return false
}

// GetFIMPathConfigs converts FIMDirectoryConfig to HostFimPathConfig
func (c *FIMConfig) GetFIMPathConfigs() []hostfimsensor.HostFimPathConfig {
	var pathConfigs []hostfimsensor.HostFimPathConfig

	for _, dirConfig := range c.Directories {
		pathConfig := hostfimsensor.HostFimPathConfig{
			Path:     dirConfig.Path,
			OnCreate: dirConfig.OnCreate,
			OnChange: dirConfig.OnChange,
			OnRemove: dirConfig.OnRemove,
			OnRename: dirConfig.OnRename,
			OnChmod:  dirConfig.OnChmod,
			OnMove:   dirConfig.OnMove,
		}
		pathConfigs = append(pathConfigs, pathConfig)
	}

	return pathConfigs
}

// GetFIMExportersConfig returns the exporters configuration for FIM
func (c *FIMConfig) GetFIMExportersConfig() exporters.ExportersConfig {
	return exporters.ExportersConfig{
		StdoutExporter:           c.Exporters.StdoutExporter,
		HTTPExporterConfig:       c.Exporters.HTTPExporterConfig,
		SyslogExporter:           c.Exporters.SyslogExporter,
		AlertManagerExporterUrls: c.Exporters.AlertManagerExporterUrls,
	}
}
