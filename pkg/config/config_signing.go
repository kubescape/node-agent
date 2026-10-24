//go:build experimental_signing

package config

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/spf13/viper"
)

const SignedConfigFileName = "config.signed.json"

func readSignedConfig(dir string) ([]byte, bool, error) {
	signedPath := filepath.Join(dir, SignedConfigFileName)
	verified, present, err := bundle.LoadSignedConfigIfPresent(signedPath, bundle.NodeAgentConfigPurpose)
	if err != nil {
		logger.L().Warning("refusing tampered or wrongly-signed node-agent config",
			helpers.String("path", signedPath),
			helpers.Error(err))
		return nil, true, fmt.Errorf("refused signed config %q: %w", signedPath, err)
	}
	if present {
		logger.L().Info("loaded root-signed node-agent config", helpers.String("path", signedPath))
	}
	return verified, present, nil
}

func readConfig(path string, errNotFound bool) error {
	viper.SetDefault("enableSignatureVerification", false)
	viper.SetDefault("bundleTrustPolicyPath", "")
	verified, signed, err := readSignedConfig(path)
	if err != nil {
		return err
	}
	if signed {
		return viper.ReadConfig(bytes.NewReader(verified))
	}
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) || errNotFound {
			return err
		}
	}
	return nil
}
