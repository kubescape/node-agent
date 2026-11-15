package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestGVisorConfigIsOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "enabled"}[enabled], func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			dir := t.TempDir()
			body := `{}`
			if enabled {
				body = `{"gVisorStart":{"enabled":true,"socketPath":"/run/kubescape/starts.sock","runtimeHandler":"gvisor","stopObservations":true}}`
			}
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.GVisorStart.Enabled != enabled {
				t.Fatal("unexpected source activation")
			}
			if enabled && cfg.GVisorStart.RuntimeHandler != "gvisor" {
				t.Fatal("runtime handler not loaded")
			}
			if cfg.GVisorStart.StopObservations != enabled {
				t.Fatal("stop observations must be opt-in")
			}
		})
	}
}
