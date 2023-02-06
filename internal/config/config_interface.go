package config

type configClient interface {
	// global configuration
	GetConfigurationData() ([]byte, error)
	ParseConfiguration(data []byte) error
}
