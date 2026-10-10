package containerwatcher

import (
	"context"
	"os"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerCallbackAsync_StandaloneDoesNotAcquirePodData(t *testing.T) {
	// Cancellation makes the synchronous metadata acquisition fail immediately;
	// it must still report an error for a real (even partially enriched) Pod.
	// Standalone registration must never enter that acquisition path.
	cases := []struct {
		name      string
		metadata  func(*containercollection.Container)
		wantError bool
	}{
		{"standalone", func(*containercollection.Container) {}, false},
		{"namespace", func(c *containercollection.Container) { c.K8s.Namespace = "test" }, true},
		{"pod", func(c *containercollection.Container) { c.K8s.PodName = "test" }, true},
		{"container name", func(c *containercollection.Container) { c.K8s.ContainerName = "test" }, true},
		{"UID", func(c *containercollection.Container) { c.K8s.PodUID = "test-uid" }, true},
		{"labels", func(c *containercollection.Container) { c.K8s.PodLabels = map[string]string{"app": "test"} }, true},
		{"sandbox", func(c *containercollection.Container) { c.SandboxId = "test-sandbox" }, true},
	}
	log := logger.L()
	level := log.GetLevel()
	require.NoError(t, log.SetLevel("error"))
	t.Cleanup(func() { log.SetWriter(os.Stderr); _ = log.SetLevel(level) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "log")
			require.NoError(t, err)
			t.Cleanup(func() { _ = output.Close() })
			log.SetWriter(output)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			cw := &ContainerWatcher{ctx: ctx, cfg: config.Config{NamespaceFilterFile: "namespaces"}, metrics: metricsmanager.NewMetricsMock()}
			c := &containercollection.Container{}
			c.Runtime.ContainerID = "runtime-test"
			c.Runtime.ContainerPID = uint32(os.Getpid())
			tc.metadata(c)
			cw.containerCallbackAsync(containercollection.PubSubEvent{Type: containercollection.EventTypeAddContainer, Container: c})
			data, err := os.ReadFile(output.Name())
			require.NoError(t, err)
			if tc.wantError {
				assert.Contains(t, string(data), "error getting shared watched container data")
			} else {
				assert.Empty(t, string(data), "standalone registration must not try to acquire Pod metadata")
			}
		})
	}
}
