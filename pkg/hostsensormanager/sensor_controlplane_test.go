package hostsensormanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// etcdProcess lays out /proc/123 for an etcd process under the host prefix: its command
// line, environment, working directory and the files of its root filesystem.
type etcdProcess struct {
	args  []string
	env   []string
	cwd   string
	files map[string]string
	dirs  []string
}

func (p etcdProcess) create(t *testing.T, prefix string) {
	t.Helper()
	proc := filepath.Join(prefix, "proc", "123")
	require.NoError(t, os.MkdirAll(proc, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), []byte(strings.Join(p.args, "\x00")+"\x00"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "environ"), []byte(strings.Join(p.env, "\x00")+"\x00"), 0644))
	if p.cwd != "" {
		require.NoError(t, os.Symlink(p.cwd, filepath.Join(proc, "cwd")))
	}
	root := filepath.Join(proc, "root")
	for _, dir := range p.dirs {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0700))
		require.NoError(t, os.Chmod(filepath.Join(root, dir), 0700))
	}
	for file, content := range p.files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, file)), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(content), 0600))
	}
}

func TestControlPlaneInfoSenseEtcdDataDir(t *testing.T) {
	dirs := []string{"/var/lib/etcd", "/var/lib/wrong", "/var/lib/infra0.etcd", "/var/lib/master-0.etcd", "/var/lib/default.etcd"}
	for _, tc := range []struct {
		name string
		proc *etcdProcess
		want string
	}{
		{name: "flag with equals", want: "/var/lib/etcd", proc: &etcdProcess{args: []string{"/usr/local/bin/etcd", "--name=master-0", "--data-dir=/var/lib/etcd"}}},
		{name: "flag with separate value", want: "/var/lib/etcd", proc: &etcdProcess{args: []string{"/usr/bin/etcd", "--data-dir", "/var/lib/etcd"}}},
		{name: "single dash flag", want: "/var/lib/etcd", proc: &etcdProcess{args: []string{"etcd", "-data-dir=/var/lib/etcd"}}},
		// OpenShift starts etcd through nice/ionice with its data directory in the environment.
		{name: "environment only", want: "/var/lib/etcd", proc: &etcdProcess{args: []string{"etcd", "--logger=zap"}, env: []string{"ETCD_DATA_DIR=/var/lib/etcd", "ETCD_NAME=master-0"}}},
		{name: "flag shadows environment", want: "/var/lib/etcd", proc: &etcdProcess{args: []string{"etcd", "--data-dir=/var/lib/etcd"}, env: []string{"ETCD_DATA_DIR=/var/lib/wrong"}}},
		{name: "configuration file ignores flags", want: "/var/lib/etcd", proc: &etcdProcess{
			args:  []string{"etcd", "--config-file=/etc/etcd/etcd.yaml", "--data-dir=/var/lib/wrong"},
			files: map[string]string{"/etc/etcd/etcd.yaml": "name: master-0\ndata-dir: /var/lib/etcd\n"}}},
		{name: "configuration file from the environment", want: "/var/lib/master-0.etcd", proc: &etcdProcess{
			args: []string{"etcd"}, env: []string{"ETCD_CONFIG_FILE=etcd.yaml", "ETCD_DATA_DIR=/var/lib/wrong"}, cwd: "/var/lib",
			files: map[string]string{"/var/lib/etcd.yaml": "name: master-0\n"}}},
		{name: "relative flag", want: "/var/lib/infra0.etcd", proc: &etcdProcess{args: []string{"etcd", "--data-dir=infra0.etcd"}, cwd: "/var/lib"}},
		{name: "default from the name", want: "/var/lib/master-0.etcd", proc: &etcdProcess{args: []string{"etcd", "--name", "master-0"}, cwd: "/var/lib"}},
		{name: "default name", want: "/var/lib/default.etcd", proc: &etcdProcess{args: []string{"etcd"}, cwd: "/var/lib"}},
		{name: "unreadable configuration file", proc: &etcdProcess{args: []string{"etcd", "--config-file=/etc/etcd/missing.yaml", "--data-dir=/var/lib/etcd"}}},
		{name: "relative path without working directory", proc: &etcdProcess{args: []string{"etcd", "--data-dir=infra0.etcd"}}},
		{name: "no etcd process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := t.TempDir()
			t.Cleanup(SetHostFSPrefixForTest(prefix))
			require.NoError(t, os.MkdirAll(filepath.Join(prefix, "proc"), 0755))
			if tc.proc != nil {
				tc.proc.dirs = dirs
				tc.proc.create(t, prefix)
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
