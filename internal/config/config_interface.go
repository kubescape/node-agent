package config

import "io"

type ConfigClient interface {
	// global configuration
	GetConfigurationData() (io.Reader, error)
	ParseConfiguration(data io.Reader) error
}
