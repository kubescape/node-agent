//go:build !experimental_signing

package config

import (
	"errors"

	"github.com/spf13/viper"
)

func readConfig(_ string, errNotFound bool) error {
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) || errNotFound {
			return err
		}
	}
	return nil
}
