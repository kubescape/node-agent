//go:build !experimental_signing

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestDefaultBuildIgnoresSignedConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"nodeName":"unsigned"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.signed.json"), []byte(`{}`), 0600))
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.Equal(t, "unsigned", cfg.NodeName)
}
