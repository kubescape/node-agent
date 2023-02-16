package config

var configContext Config

func init() {
	configContext = Config{}
}

func GetConfigurationConfigContext() *Config {
	return &configContext
}
