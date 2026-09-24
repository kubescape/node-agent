package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Exercise main itself: a typo must fail before cluster metadata loading or
// Kubernetes startup can hide the actionable configuration error.
func TestMainRejectsHostSensorExclusionsBeforeStartup(t *testing.T) {
	if os.Getenv("NODE_AGENT_TEST_HOST_SENSOR_STARTUP") == "1" {
		main()
		return
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"hostSensorEnabled":true,"hostSensorExcludedSensors":["typo"]}`), 0600))
	t.Setenv("CONFIG_DIR", dir)
	t.Setenv("HOSTSENSORENABLED", "true")
	t.Setenv("HOSTSENSOREXCLUDEDSENSORS", "typo")
	t.Setenv("NODE_AGENT_TEST_HOST_SENSOR_STARTUP", "1")
	executable, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, "-test.run=^TestMainRejectsHostSensorExclusionsBeforeStartup$").CombinedOutput()
	require.NoError(t, ctx.Err(), "startup failed to reject exclusions promptly: %s", output)
	require.Error(t, err)
	require.Contains(t, string(output), "invalid host sensor configuration")
	require.Contains(t, string(output), "unknown excluded host sensor")
	require.Contains(t, string(output), "typo")
	require.NotContains(t, string(output), "load clusterData error")
}
