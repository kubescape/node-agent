package hostsensormanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControlPlaneInfoSenseEtcdDataDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline string
		want    string
	}{
		{name: "equals form", cmdline: "/usr/local/bin/etcd\x00--name=master-0\x00--data-dir=/var/lib/etcd\x00", want: "/var/lib/etcd"},
		{name: "separate value", cmdline: "/usr/bin/etcd\x00--data-dir\x00/var/lib/etcd\x00", want: "/var/lib/etcd"},
		{name: "no data-dir argument", cmdline: "/usr/bin/etcd\x00--name=master-0\x00"},
		{name: "no etcd process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := t.TempDir()
			t.Cleanup(SetHostFSPrefixForTest(prefix))
			require.NoError(t, os.MkdirAll(filepath.Join(prefix, "proc"), 0755))
			if tc.cmdline != "" {
				proc := filepath.Join(prefix, "proc", "123")
				require.NoError(t, os.MkdirAll(proc, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), []byte(tc.cmdline), 0644))
				// The directory is read inside the etcd process's root filesystem.
				dataDir := filepath.Join(proc, "root", "var", "lib", "etcd")
				require.NoError(t, os.MkdirAll(dataDir, 0700))
				require.NoError(t, os.Chmod(dataDir, 0700))
			}
			data, err := NewControlPlaneInfoSensor("master-0").Sense()
			require.NoError(t, err)
			spec := data.(*ControlPlaneInfoSpec)
			if tc.want == "" {
				require.Nil(t, spec.EtcdDataDir)
				return
			}
			require.NotNil(t, spec.EtcdDataDir)
			require.Equal(t, tc.want, spec.EtcdDataDir.Path)
			require.Equal(t, 0700, spec.EtcdDataDir.Permissions)
			require.NotNil(t, spec.EtcdDataDir.Ownership)
			require.Empty(t, spec.EtcdDataDir.Content)
		})
	}
}
