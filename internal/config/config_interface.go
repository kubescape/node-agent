package config

type configClient interface {
	// global configuration
	GetConfigurutionData() ([]byte, error)
	ParseConfiguration() error
}
