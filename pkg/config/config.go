package config

import (
	"node-agent/pkg/rulemanager/exporters"
	"time"

	"github.com/spf13/viper"
)

const NodeNameEnvVar = "NODE_NAME"

type Config struct {
	EnableFullPathTracing    bool                      `mapstructure:"fullPathTracingEnabled"`
	EnableApplicationProfile bool                      `mapstructure:"applicationProfileServiceEnabled"`
	EnablePrometheusExporter bool                      `mapstructure:"prometheusExporterEnabled"`
	EnableRuntimeDetection   bool                      `mapstructure:"runtimeDetectionEnabled"`
	EnableNetworkTracing     bool                      `mapstructure:"networkServiceEnabled"`
	EnableRelevancy          bool                      `mapstructure:"relevantCVEServiceEnabled"`
	InitialDelay             time.Duration             `mapstructure:"initialDelay"`
	MaxSniffingTime          time.Duration             `mapstructure:"maxSniffingTimePerContainer"`
	UpdateDataPeriod         time.Duration             `mapstructure:"updateDataPeriod"`
	Exporters                exporters.ExportersConfig `mapstructure:"exporters"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	viper.SetDefault("fullPathTracingEnabled", true)
	viper.SetDefault("initialDelay", 2*time.Minute)

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}
