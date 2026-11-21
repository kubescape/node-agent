package hostsensormanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKernelVersionSensor(t *testing.T) {
	s := NewKernelVersionSensor("worker-1")
	require.NotNil(t, s)
	assert.Equal(t, "KernelVersion", s.GetKind())
	assert.Equal(t, "kernelversions", s.GetPluralKind())

	tmp := t.TempDir()
	restore := SetHostFSPrefixForTest(tmp)
	defer restore()

	// Missing /proc/version returns an error
	_, err := s.Sense()
	assert.Error(t, err)

	procDir := filepath.Join(tmp, "proc")
	require.NoError(t, os.MkdirAll(procDir, 0o755))
	wantVersion := "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-001)"
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "version"), []byte(wantVersion), 0o644))

	res, err := s.Sense()
	require.NoError(t, err)
	spec, ok := res.(*KernelVersionSpec)
	require.True(t, ok)
	assert.Equal(t, "worker-1", spec.NodeName)
	assert.Equal(t, wantVersion, spec.Content)
}

func TestLinuxSecurityHardeningSensor(t *testing.T) {
	s := NewLinuxSecurityHardeningSensor("worker-2")
	require.NotNil(t, s)
	assert.Equal(t, "LinuxSecurityHardeningStatus", s.GetKind())
	assert.Equal(t, "linuxsecurityhardeningstatuses", s.GetPluralKind())

	tmp := t.TempDir()
	restore := SetHostFSPrefixForTest(tmp)
	defer restore()

	// Neither AppArmor nor SELinux files exist
	res, err := s.Sense()
	require.NoError(t, err)
	spec, ok := res.(*LinuxSecurityHardeningSpec)
	require.True(t, ok)
	assert.Equal(t, "worker-2", spec.NodeName)
	assert.Equal(t, "unloaded", spec.AppArmor)
	assert.Equal(t, "not found", spec.SeLinux)

	// Empty AppArmor profiles file -> "stopped"
	appArmorDir := filepath.Join(tmp, "sys", "kernel", "security", "apparmor")
	require.NoError(t, os.MkdirAll(appArmorDir, 0o755))
	appArmorFile := filepath.Join(appArmorDir, "profiles")
	require.NoError(t, os.WriteFile(appArmorFile, nil, 0o644))

	res, err = s.Sense()
	require.NoError(t, err)
	spec = res.(*LinuxSecurityHardeningSpec)
	assert.Equal(t, "stopped", spec.AppArmor)

	// Non-empty AppArmor and SELinux files
	require.NoError(t, os.WriteFile(appArmorFile, []byte("docker-default (enforce)"), 0o644))
	seLinuxDir := filepath.Join(tmp, "etc", "selinux")
	require.NoError(t, os.MkdirAll(seLinuxDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seLinuxDir, "semanage.conf"), []byte("module-store = direct"), 0o644))

	res, err = s.Sense()
	require.NoError(t, err)
	spec = res.(*LinuxSecurityHardeningSpec)
	assert.Equal(t, "docker-default (enforce)", spec.AppArmor)
	assert.Equal(t, "module-store = direct", spec.SeLinux)
}

func TestExtractClientCAFromKubeletConfig(t *testing.T) {
	yamlWithCA := []byte(`
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
`)
	caPath, err := extractClientCAFromKubeletConfig(yamlWithCA)
	require.NoError(t, err)
	assert.Equal(t, "/etc/kubernetes/pki/ca.crt", caPath)

	caPath, err = extractClientCAFromKubeletConfig([]byte("kind: KubeletConfiguration\n"))
	require.NoError(t, err)
	assert.Equal(t, "", caPath)

	_, err = extractClientCAFromKubeletConfig([]byte(":::invalid-yaml"))
	assert.Error(t, err)
}

func TestProcessDetailsAndEtcdHelpers(t *testing.T) {
	p := ProcessDetails{
		PID:     123,
		CmdLine: []string{"/usr/bin/etcd", "--name=etcd-0", "--data-dir", "/var/lib/etcd", "-v"},
	}

	assert.Equal(t, "/usr/bin/etcd --name=etcd-0 --data-dir /var/lib/etcd -v", p.RawCmd())

	val, ok := p.GetArg("--name")
	assert.True(t, ok)
	assert.Equal(t, "etcd-0", val)

	val, ok = p.GetArg("--data-dir")
	assert.True(t, ok)
	assert.Equal(t, "/var/lib/etcd", val)

	val, ok = p.GetArg("-v")
	assert.True(t, ok)
	assert.Equal(t, "", val)

	_, ok = p.GetArg("--missing")
	assert.False(t, ok)

	flagVal, ok := etcdFlag(&p, "name")
	assert.True(t, ok)
	assert.Equal(t, "etcd-0", flagVal)

	_, ok = etcdFlag(&p, "unknown")
	assert.False(t, ok)

	// processEnviron
	assert.Empty(t, processEnviron(filepath.Join(t.TempDir(), "missing-environ")))

	envFile := filepath.Join(t.TempDir(), "environ")
	require.NoError(t, os.WriteFile(envFile, []byte("ETCD_NAME=main\x00ETCD_DATA_DIR=/data/etcd\x00MALFORMED\x00"), 0o600))
	env := processEnviron(envFile)
	assert.Equal(t, map[string]string{
		"ETCD_NAME":     "main",
		"ETCD_DATA_DIR": "/data/etcd",
	}, env)
}
