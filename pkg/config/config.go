package config

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/spf13/viper"
)

const NodeNameEnvVar = "NODE_NAME"
const PodNameEnvVar = "POD_NAME"
const NamespaceEnvVar = "NAMESPACE_NAME"

type Config struct {
	Exporters                      exporters.ExportersConfig       `mapstructure:"exporters"`
	InitialDelay                   time.Duration                   `mapstructure:"initialDelay"`
	MaxSniffingTime                time.Duration                   `mapstructure:"maxSniffingTimePerContainer"`
	UpdateDataPeriod               time.Duration                   `mapstructure:"updateDataPeriod"`
	MaxDelaySeconds                int                             `mapstructure:"maxDelaySeconds"`
	MaxJitterPercentage            int                             `mapstructure:"maxJitterPercentage"`
	MaxImageSize                   int64                           `mapstructure:"maxImageSize"`
	MaxSBOMSize                    int                             `mapstructure:"maxSBOMSize"`
	MaxTsProfileSize               int64                           `mapstructure:"maxTsProfileSize"`
	EnableFullPathTracing          bool                            `mapstructure:"fullPathTracingEnabled"`
	EnableApplicationProfile       bool                            `mapstructure:"applicationProfileServiceEnabled"`
	EnableMalwareDetection         bool                            `mapstructure:"malwareDetectionEnabled"`
	EnablePrometheusExporter       bool                            `mapstructure:"prometheusExporterEnabled"`
	EnableRuntimeDetection         bool                            `mapstructure:"runtimeDetectionEnabled"`
	EnableHttpDetection            bool                            `mapstructure:"httpDetectionEnabled"`
	EnableNetworkTracing           bool                            `mapstructure:"networkServiceEnabled"`
	EnableNetworkStreaming         bool                            `mapstructure:"networkStreamingEnabled"`
	EnableNodeProfile              bool                            `mapstructure:"nodeProfileServiceEnabled"`
	EnableHostMalwareSensor        bool                            `mapstructure:"hostMalwareSensorEnabled"`
	EnableHostNetworkSensor        bool                            `mapstructure:"hostNetworkSensorEnabled"`
	NodeProfileInterval            time.Duration                   `mapstructure:"nodeProfileInterval"`
	EnableSeccomp                  bool                            `mapstructure:"seccompServiceEnabled"`
	ExcludeLabels                  map[string]string               `mapstructure:"excludeLabels"`
	ExcludeNamespaces              []string                        `mapstructure:"excludeNamespaces"`
	IncludeNamespaces              []string                        `mapstructure:"includeNamespaces"`
	EnableSbomGeneration           bool                            `mapstructure:"sbomGenerationEnabled"`
	EnableEmbeddedSboms            bool                            `mapstructure:"enableEmbeddedSBOMs"`
	NamespaceName                  string                          `mapstructure:"namespaceName"`
	NodeName                       string                          `mapstructure:"nodeName"`
	PodName                        string                          `mapstructure:"podName"`
	KubernetesMode                 bool                            `mapstructure:"kubernetesMode"`
	NetworkStreamingInterval       time.Duration                   `mapstructure:"networkStreamingInterval"`
	WorkerPoolSize                 int                             `mapstructure:"workerPoolSize"`
	EventBatchSize                 int                             `mapstructure:"eventBatchSize"`
	TestMode                       bool                            `mapstructure:"testMode"`
	ExcludeJsonPaths               []string                        `mapstructure:"excludeJsonPaths"`
	ProfilesCacheRefreshRate       time.Duration                   `mapstructure:"profilesCacheRefreshRate"`
	RuleCoolDown                   rulecooldown.RuleCooldownConfig `mapstructure:"ruleCooldown"`
	EnablePartialProfileGeneration bool                            `mapstructure:"partialProfileGenerationEnabled"`
	ProcfsScanInterval             time.Duration                   `mapstructure:"procfsScanInterval"`
	CelConfigCache                 cache.FunctionCacheConfig       `mapstructure:"celConfigCache"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")

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
	viper.SetDefault("networkStreamingEnabled", false)
	viper.SetDefault("kubernetesMode", true)
	viper.SetDefault("networkStreamingInterval", 2*time.Minute)
	viper.SetDefault("workerPoolSize", 2000) // Increased from 50 to handle higher event volumes
	viper.SetDefault("eventBatchSize", 2500)
	viper.SetDefault("testMode", false)
	viper.SetDefault("enableEmbeddedSBOMs", false)
	viper.SetDefault("profilesCacheRefreshRate", 1*time.Minute)
	viper.SetDefault("ruleCooldown.ruleCooldownDuration", 1*time.Hour)
	viper.SetDefault("ruleCooldown.ruleCooldownAfterCount", 1)
	viper.SetDefault("ruleCooldown.ruleCooldownOnProfileFailure", true)
	viper.SetDefault("ruleCooldown.ruleCooldownMaxSize", 10000)
	viper.SetDefault("partialProfileGenerationEnabled", true)
	viper.SetDefault("procfsScanInterval", 5*time.Second)
	viper.SetDefault("celConfigCache.maxSize", 1000)
	viper.SetDefault("celConfigCache.ttl", 1*time.Minute)
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
	for k, v := range c.ExcludeLabels {
		if labelValue, ok := labels[k]; ok {
			if strings.EqualFold(labelValue, v) {
				return true
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
