package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadHostSensorExclusions(t *testing.T) {
	for _, tt := range []struct {
		name, content, env string
		want               []string
	}{
		{"omitted", `{}`, "", []string{}},
		{"empty", `{"hostSensorExcludedSensors":[]}`, "", []string{}},
		{"json", `{"hostSensorExcludedSensors":["KubeProxyInfo","CNIInfo"]}`, "", []string{"KubeProxyInfo", "CNIInfo"}},
		{"empty environment preserves file", `{"hostSensorExcludedSensors":["KubeProxyInfo"]}`, "", []string{"KubeProxyInfo"}},
		{"environment", `{}`, "KubeProxyInfo", []string{"KubeProxyInfo"}},
		{"comma-separated environment", `{}`, "KubeProxyInfo,CNIInfo", []string{"KubeProxyInfo", "CNIInfo"}},
		{"environment overrides file", `{"hostSensorExcludedSensors":["CNIInfo"]}`, "KubeProxyInfo", []string{"KubeProxyInfo"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			t.Setenv("HOSTSENSOREXCLUDEDSENSORS", tt.env)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(dir+"/config.json", []byte(tt.content), 0600))
			cfg, err := LoadConfig(dir)
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.HostSensorExcludedSensors)
		})
	}
}
