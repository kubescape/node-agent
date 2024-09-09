package config

import (
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
	MaxJitterPercentage      int                       `mapstructure:"maxJitterPercentage"`
	EnableFullPathTracing    bool                      `mapstructure:"fullPathTracingEnabled"`
	EnableApplicationProfile bool                      `mapstructure:"applicationProfileServiceEnabled"`
	EnableMalwareDetection   bool                      `mapstructure:"malwareDetectionEnabled"`
	EnablePrometheusExporter bool                      `mapstructure:"prometheusExporterEnabled"`
	EnableRuntimeDetection   bool                      `mapstructure:"runtimeDetectionEnabled"`
	EnableEndpointDetection  bool                      `mapstructure:"endpointDetectionEnabled"`
	EnableNetworkTracing     bool                      `mapstructure:"networkServiceEnabled"`
	EnableRelevancy          bool                      `mapstructure:"relevantCVEServiceEnabled"`
	EnableNodeProfile        bool                      `mapstructure:"nodeProfileServiceEnabled"`
	NodeProfileInterval      time.Duration             `mapstructure:"nodeProfileInterval"`
	EnableSeccomp            bool                      `mapstructure:"seccompServiceEnabled"`
	ExcludeNamespaces        []string                  `mapstructure:"excludeNamespaces"`
	IncludeNamespaces        []string                  `mapstructure:"includeNamespaces"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	viper.SetDefault("fullPathTracingEnabled", true)
	viper.SetDefault("initialDelay", 2*time.Minute)
	viper.SetDefault("nodeProfileInterval", 10*time.Minute)
	viper.SetDefault("maxJitterPercentage", 5)

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
