package config

import (
	"time"

	"github.com/spf13/viper"
)

const NodeNameEnvVar = "NODE_NAME"

type ClusterData struct {
	AccountID   string `mapstructure:"accountID"`
	ClusterName string `mapstructure:"clusterName"`
}

// LoadClusterData reads configuration from file or environment variables.
func LoadClusterData(path string) (ClusterData, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("clusterData")
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return ClusterData{}, err
	}

	var config ClusterData
	err = viper.Unmarshal(&config)
	return config, err
}

type Config struct {
	EnableRelevancy  bool          `mapstructure:"relevantCVEServiceEnabled"`
	MaxSniffingTime  time.Duration `mapstructure:"maxSniffingTimePerContainer"`
	UpdateDataPeriod time.Duration `mapstructure:"updateDataPeriod"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = viper.Unmarshal(&config)
	return config, err
}
