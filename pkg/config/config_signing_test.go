//go:build experimental_signing

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSignedConfigRejectsInvalidArtifactBeforeUnsignedFallback(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"nodeName":"unsigned"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, SignedConfigFileName), []byte(`{}`), 0600))
	_, err := LoadConfig(dir)
	require.ErrorContains(t, err, "refused signed config")
}
