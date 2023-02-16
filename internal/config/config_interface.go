package config

import "io"

type ConfigClient interface {
	GetConfigurationData() (io.Reader, error)
	ParseConfiguration(configData ConfigDataInterface, data io.Reader) error
}
