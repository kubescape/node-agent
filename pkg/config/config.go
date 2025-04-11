package config

import (
	"os"
	"slices"
	"time"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/spf13/viper"
)

const NodeNameEnvVar = "NODE_NAME"
const PodNameEnvVar = "POD_NAME"
const NamespaceEnvVar = "NAMESPACE_NAME"

type Config struct {
	Exporters                exporters.ExportersConfig `mapstructure:"exporters"`
	InitialDelay             time.Duration             `mapstructure:"initialDelay"`
	MaxSniffingTime          time.Duration             `mapstructure:"maxSniffingTimePerContainer"`
	UpdateDataPeriod         time.Duration             `mapstructure:"updateDataPeriod"`
	MaxDelaySeconds          int                       `mapstructure:"maxDelaySeconds"`
	MaxJitterPercentage      int                       `mapstructure:"maxJitterPercentage"`
	MaxImageSize             int64                     `mapstructure:"maxImageSize"`
	MaxSBOMSize              int                       `mapstructure:"maxSBOMSize"`
	EnableFullPathTracing    bool                      `mapstructure:"fullPathTracingEnabled"`
	EnableApplicationProfile bool                      `mapstructure:"applicationProfileServiceEnabled"`
	EnableMalwareDetection   bool                      `mapstructure:"malwareDetectionEnabled"`
	EnablePrometheusExporter bool                      `mapstructure:"prometheusExporterEnabled"`
	EnableRuntimeDetection   bool                      `mapstructure:"runtimeDetectionEnabled"`
	EnableHttpDetection      bool                      `mapstructure:"httpDetectionEnabled"`
	EnableNetworkTracing     bool                      `mapstructure:"networkServiceEnabled"`
	EnableNodeProfile        bool                      `mapstructure:"nodeProfileServiceEnabled"`
	EnableHostMalwareSensor  bool                      `mapstructure:"hostMalwareSensorEnabled"`
	EnableHostNetworkSensor  bool                      `mapstructure:"hostNetworkSensorEnabled"`
	NodeProfileInterval      time.Duration             `mapstructure:"nodeProfileInterval"`
	EnableSeccomp            bool                      `mapstructure:"seccompServiceEnabled"`
	ExcludeNamespaces        []string                  `mapstructure:"excludeNamespaces"`
	IncludeNamespaces        []string                  `mapstructure:"includeNamespaces"`
	EnableSbomGeneration     bool                      `mapstructure:"sbomGenerationEnabled"`
	NamespaceName            string                    `mapstructure:"namespaceName"`
	NodeName                 string                    `mapstructure:"nodeName"`
	PodName                  string                    `mapstructure:"podName"`
	KubernetesMode           bool                      `mapstructure:"kubernetesMode"`
	EnableHostManager        bool                      `mapstructure:"hostManagerEnabled"`
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
	viper.SetDefault("namespaceName", os.Getenv(NamespaceEnvVar))
	viper.SetDefault("nodeName", os.Getenv(NodeNameEnvVar))
	viper.SetDefault("podName", os.Getenv(PodNameEnvVar))
	viper.SetDefault("hostMalwareSensorEnabled", false)
	viper.SetDefault("hostNetworkSensorEnabled", false)
	viper.SetDefault("kubernetesMode", true)

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
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
