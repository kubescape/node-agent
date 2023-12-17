package utils

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetCNIConfigPath(t *testing.T) {
	uid_tests := []struct {
		name     string
		process  string
		pid      int32
		expected string
	}{
		{
			name:     "kubelet_kind",
			process:  "/usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --node-ip=172.18.0.2 --node-labels= --pod-infra-container-image=registry.k8s.io/pause:3.8 --provider-id=kind://docker/cis-test/cis-test-control-plane --fail-swap-on=false --cgroup-root=/kubelet",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni --register-node=true --v=2",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation_with_custom_runtime_endpoint",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni --container-runtime-endpoint=/run/containerd/containerd.sock",
			pid:      15,
			expected: "/etc/cni/",
			//expected: "/run/containerd/",
		},
		{
			name:     "kubelet_manual_installation_with_custom_cni_dir",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni --container-runtime-endpoint=/run/containerd/containerd.sock --cni-conf-dir=/var/lib/cni/",
			pid:      15,
			expected: "/var/lib/cni/",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// create ProcessDetails object to pass it to GetCNIConfigPath
			proc := &ProcessDetails{
				CmdLine: strings.Split(tt.process, " "),
				PID:     tt.pid,
			}
			cniConfigPath := GetCNIConfigPath(ctx, proc)

			if !assert.Equal(t, tt.expected, cniConfigPath) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_getConfigDirPath(t *testing.T) {
	uid_tests := []struct {
		name             string
		cmdline          string
		defaultConfigDir string
		configDirArgName string
		expected         string
	}{
		{
			name:             "crio",
			cmdline:          "/usr/bin/crio --config-dir /etc/crio/crio.d",
			defaultConfigDir: "/etc/crio/crio.conf.d/",
			configDirArgName: "--config-dir",
			expected:         "/etc/crio/crio.d",
		},
		{
			name:             "crio_default",
			cmdline:          "/usr/bin/crio",
			defaultConfigDir: "/etc/crio/crio.conf.d",
			configDirArgName: "--config-dir",
			expected:         "/etc/crio/crio.conf.d",
		},
		{
			name:             "containerd",
			cmdline:          "/usr/bin/containerd",
			defaultConfigDir: "/etc/containerd/containerd.conf.d/",
			configDirArgName: "",
			expected:         "/etc/containerd/containerd.conf.d",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			// create ContainerRuntimeInfo
			cr := &ContainerRuntimeInfo{
				properties: &containerRuntimeProperties{
					DefaultConfigDir: tt.defaultConfigDir,
					ConfigDirArgName: tt.configDirArgName,
				},
				process: &ProcessDetails{
					CmdLine: strings.Split(tt.cmdline, " "),
				},
				rootDir: "",
			}

			configDirPath := cr.getConfigDirPath()

			if !assert.Equal(t, tt.expected, configDirPath) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_getConfigPath(t *testing.T) {
	uid_tests := []struct {
		name              string
		cmdLine           string
		defaultConfigPath string
		configArgName     string
		expected          string
	}{
		{
			name:              "crio",
			cmdLine:           "/usr/bin/crio --config /etc/personaldir/crio.conf",
			configArgName:     "--config",
			defaultConfigPath: "/etc/crio/crio.conf",
			expected:          "/etc/personaldir/crio.conf",
		},
		{
			name:              "crio_default",
			cmdLine:           "/usr/bin/crio",
			configArgName:     "--config",
			defaultConfigPath: "/etc/crio/crio.conf",
			expected:          "/etc/crio/crio.conf",
		},
		{
			name:              "containerd",
			cmdLine:           "/usr/bin/containerd --config /etc/personaldir/containerd.toml",
			configArgName:     "--config",
			defaultConfigPath: "/etc/containerd/config.toml",
			expected:          "/etc/personaldir/containerd.toml",
		},
		{
			name:              "containerd_default",
			cmdLine:           "/usr/bin/containerd",
			configArgName:     "--config",
			defaultConfigPath: "/etc/containerd/config.toml",
			expected:          "/etc/containerd/config.toml",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			// create ContainerRuntimeInfo
			cr := &ContainerRuntimeInfo{
				properties: &containerRuntimeProperties{
					DefaultConfigPath: tt.defaultConfigPath,
					ConfigArgName:     tt.configArgName,
				},
				process: &ProcessDetails{
					CmdLine: strings.Split(tt.cmdLine, " "),
				},
				rootDir: "",
			}

			configPath := cr.getConfigPath()

			if !assert.Equal(t, tt.expected, configPath) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_getCNIConfigDirFromConfig(t *testing.T) {
	uid_tests := []struct {
		name                   string
		cmdLine                string
		defaultConfigDir       string
		defaultConfigPath      string
		parseCNIFromConfigFunc func(string) (string, error)
		expected               string
	}{
		{
			name:                   "containerd",
			cmdLine:                "/usr/bin/containerd",
			defaultConfigDir:       "testdata/testCNI/",
			defaultConfigPath:      "testdata/testCNI/containerd.toml",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigContainerd,
			expected:               "/etc/cni/net.mk",
		},
		{
			name:                   "crio",
			cmdLine:                "/usr/bin/crio",
			defaultConfigDir:       "testdata/testCNI/crio.d",
			defaultConfigPath:      "testdata/testCNI/crio.conf",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigCrio,
			expected:               "/etc/cni/net.d/03",
		},
		{
			name:                   "crio_with_wrong_config_dir",
			cmdLine:                "/usr/bin/crio",
			defaultConfigDir:       "testdata/testCNI/crio.doesnt/exists/",
			defaultConfigPath:      "testdata/testCNI/crio.conf",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigCrio,
			expected:               "/etc/cni/net.d/",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// create ContainerRuntimeInfo
			cr := &ContainerRuntimeInfo{
				properties: &containerRuntimeProperties{
					DefaultConfigDir:       tt.defaultConfigDir,
					DefaultConfigPath:      tt.defaultConfigPath,
					ParseCNIFromConfigFunc: tt.parseCNIFromConfigFunc,
				},
				process: &ProcessDetails{
					CmdLine: strings.Split(tt.cmdLine, " "),
				},
				rootDir: "",
			}

			cniConfigDirFormFile := cr.getCNIConfigDirFromConfig(ctx)

			if !assert.Equal(t, tt.expected, cniConfigDirFormFile) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_getCNIConfigDirFromProcess(t *testing.T) {
	uid_tests := []struct {
		name                string
		cmdLine             string
		cniConfigDirArgName string
		expected            string
	}{
		{
			name:                "containerd",
			cmdLine:             "/usr/bin/containerd",
			cniConfigDirArgName: "",
			expected:            "",
		},
		{
			name:                "crio_with_flag",
			cmdLine:             "/usr/bin/crio --cni-config-dir /etc/crio/cni/",
			cniConfigDirArgName: "--cni-config-dir",
			expected:            "/etc/crio/cni/",
		},
		{
			name:                "crio_without_flag",
			cmdLine:             "/usr/bin/crio",
			cniConfigDirArgName: "--cni-config-dir",
			expected:            "",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			// create ContainerRuntimeInfo
			cr := &ContainerRuntimeInfo{
				properties: &containerRuntimeProperties{
					CNIConfigDirArgName: tt.cniConfigDirArgName,
				},
				process: &ProcessDetails{
					CmdLine: strings.Split(tt.cmdLine, " "),
				},
				rootDir: "",
			}
			cniConfig := cr.getCNIConfigDirFromProcess()

			if !assert.Equal(t, tt.expected, cniConfig) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_parseCNIPathsFromConfigContainerd(t *testing.T) {
	uid_tests := []struct {
		name        string
		path        string
		expectedRes string
		wantErr     bool
	}{
		{
			name:        "fileexists_paramsexist",
			path:        "testdata/testCNI/containerd.toml",
			expectedRes: "/etc/cni/net.mk",
			wantErr:     false,
		},
		{
			name:        "file_not_exit",
			path:        "testdata/testCNI/bla.toml",
			expectedRes: "",
			wantErr:     true,
		},
		{
			name:        "fileexists_noparams",
			path:        "testdata/testCNI/containerd_noparams.toml",
			expectedRes: "",
			wantErr:     false,
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			CNIConfigDir, err := parseCNIConfigDirFromConfigContainerd(tt.path)

			if err != nil {
				if !tt.wantErr {
					assert.NoError(t, err)
				}

			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRes, CNIConfigDir)
			}

		})
	}

}

func Test_parseCNIPathsFromConfigCrio(t *testing.T) {
	uid_tests := []struct {
		name        string
		path        string
		expectedRes string
		wantErr     bool
	}{
		{
			name:        "fileexists_paramsexist",
			path:        "testdata/testCNI/crio.conf",
			expectedRes: "/etc/cni/net.d/",
			wantErr:     false,
		},
		{
			name:        "file_not_exit",
			path:        "testdata/testCNI/bla.toml",
			expectedRes: "",
			wantErr:     true,
		},
		{
			name:        "fileexists_noparams",
			path:        "testdata/testCNI/crio_noparams.conf",
			expectedRes: "",
			wantErr:     false,
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			CNIConfigDir, err := parseCNIConfigDirFromConfigCrio(tt.path)

			if err != nil {
				if !tt.wantErr {
					assert.NoError(t, err)
				}

			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRes, CNIConfigDir)
			}

		})
	}

}

func Test_newContainerRuntime(t *testing.T) {
	uid_tests := []struct {
		name          string
		socket        string
		expectedError string
		expected      string
	}{
		{
			name:          "containerd",
			expectedError: "newContainerRuntime - Failed to locate process for CRIKind containerd",
			expected:      "containerd",
		},
		{
			name:          "crio",
			expectedError: "newContainerRuntime - Failed to locate process for CRIKind crio",
			expected:      "crio",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newContainerRuntime(tt.name)
			if err != nil {
				if !assert.EqualError(t, err, tt.expectedError) {
					t.Log(err)
				}
			}
		})
	}
}

func Test_CNIConfigDirFromKubelet(t *testing.T) {
	uid_tests := []struct {
		name     string
		process  string
		pid      int32
		expected string
	}{
		{
			name:     "kubelet_kind",
			process:  "/usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --node-ip=172.18.0.2 --node-labels= --pod-infra-container-image=registry.k8s.io/pause:3.8 --provider-id=kind://docker/cis-test/cis-test-control-plane --fail-swap-on=false --cgroup-root=/kubelet",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni --register-node=true --v=2",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation_with_custom_runtime_endpoint",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation_with_custom_cni_dir",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni --cni-conf-dir=/var/lib/cni/",
			pid:      15,
			expected: "/var/lib/cni/",
		},
		{
			name:     "kubelet_manual_installation_without_remote_and_endpoint",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni",
			pid:      15,
			expected: "/etc/cni/",
		},
		{
			name:     "kubelet_manual_installation_with_remote",
			process:  "/usr/local/bin/kubelet --config=/var/lib/kubelet/kubelet-config.yaml --container-runtime=remote --image-pull-progress-deadline=2m --kubeconfig=/var/lib/kubelet/kubeconfig --network-plugin=cni",
			pid:      15,
			expected: "/etc/cni/",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// create ProcessDetails object to pass it to GetCNIConfigPath
			proc := &ProcessDetails{
				CmdLine: strings.Split(tt.process, " "),
				PID:     tt.pid,
			}
			cniConfigPath := GetCNIConfigPath(ctx, proc)

			if !assert.Equal(t, tt.expected, cniConfigPath) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}

func Test_getCNIConfigDir(t *testing.T) {
	uid_tests := []struct {
		name                   string
		cmdLine                string
		defaultConfigDir       string
		defaultConfigPath      string
		cniConfigDirArgName    string
		parseCNIFromConfigFunc func(string) (string, error)
		expected               string
	}{
		{
			name:                   "containerd",
			cmdLine:                "/usr/bin/containerd",
			defaultConfigDir:       "testdata/testCNI/",
			defaultConfigPath:      "testdata/testCNI/containerd.toml",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigContainerd,
			cniConfigDirArgName:    "",
			expected:               "/etc/cni/net.mk",
		},
		{
			name:                   "crio",
			cmdLine:                "/usr/bin/crio",
			defaultConfigDir:       "testdata/testCNI/crio.d",
			defaultConfigPath:      "testdata/testCNI/crio.conf",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigCrio,
			cniConfigDirArgName:    "",
			expected:               "/etc/cni/net.d/03",
		},
		{
			name:                   "crio_cni_from_process",
			cmdLine:                "/usr/bin/crio --cni-config-dir=/var/lib/cni/",
			defaultConfigDir:       "",
			defaultConfigPath:      "",
			parseCNIFromConfigFunc: parseCNIConfigDirFromConfigCrio,
			cniConfigDirArgName:    "--cni-config-dir",
			expected:               "/var/lib/cni/",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// create ContainerRuntimeInfo
			cr := &ContainerRuntimeInfo{
				properties: &containerRuntimeProperties{
					DefaultConfigDir:       tt.defaultConfigDir,
					DefaultConfigPath:      tt.defaultConfigPath,
					ParseCNIFromConfigFunc: tt.parseCNIFromConfigFunc,
					CNIConfigDirArgName:    tt.cniConfigDirArgName,
				},
				process: &ProcessDetails{
					CmdLine: strings.Split(tt.cmdLine, " "),
				},
				rootDir: "",
			}

			cniConfigDirFormFile := cr.getCNIConfigDir(ctx)

			if !assert.Equal(t, tt.expected, cniConfigDirFormFile) {
				t.Logf("%s has different output\n", tt.name)
			}
		})
	}
}
