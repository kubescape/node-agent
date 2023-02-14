package config

import "io"

type ConfigClient interface {
	GetConfigurationData() (io.Reader, error)
	ParseConfiguration(data io.Reader) error
}
