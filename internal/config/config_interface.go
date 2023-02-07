package config

type ConfigClient interface {
	// global configuration
	GetConfigurationData() ([]byte, error)
	ParseConfiguration(data []byte) error
}
