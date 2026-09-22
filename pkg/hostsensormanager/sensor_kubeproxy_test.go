package hostsensormanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKubeProxyInfoSense(t *testing.T) {
	for _, present := range []bool{false, true} {
		name := "absent"
		if present {
			name = "present"
		}
		t.Run(name, func(t *testing.T) {
			old := hostFSPrefix
			hostFSPrefix = t.TempDir()
			t.Cleanup(func() { hostFSPrefix = old })
			require.NoError(t, os.MkdirAll(filepath.Join(hostFSPrefix, "proc"), 0755))
			if present {
				proc := filepath.Join(hostFSPrefix, "proc", "123")
				require.NoError(t, os.MkdirAll(proc, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), []byte("/usr/bin/kube-proxy\x00--hostname-override=test-node\x00"), 0644))
			}
			data, err := NewKubeProxyInfoSensor("test-node").Sense()
			if !present {
				require.ErrorContains(t, err, "failed to locate kube-proxy process")
				require.ErrorContains(t, err, "not found")
				return
			}
			require.NoError(t, err)
			spec := data.(*KubeProxyInfoSpec)
			require.Equal(t, "test-node", spec.NodeName)
			require.Equal(t, "/usr/bin/kube-proxy --hostname-override=test-node", spec.CmdLine)
		})
	}
}
