package config

import "io"

type ConfigClient interface {
	GetConfigurationReader() (io.Reader, error)
	ParseConfiguration(configData ConfigDataInterface, data io.Reader) (ConfigDataInterface, error)
}
