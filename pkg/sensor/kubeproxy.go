package sensor

import (
	"context"
	"fmt"

	sensorDs "node-agent/pkg/sensor/datastructures"
	sensorUtils "node-agent/pkg/sensor/internal/utils"

	"github.com/kubescape/go-logger/helpers"
)

const (
	kubeProxyExe = "kube-proxy"
)

// KubeProxyInfo holds information about kube-proxy process
type KubeProxyInfo struct {
	// Information about the kubeconfig file of kube-proxy
	KubeConfigFile *sensorDs.FileInfo `json:"kubeConfigFile,omitempty"`

	// Raw cmd line of kubelet process
	CmdLine string `json:"cmdLine"`
}

// SenseKubeProxyInfo return `KubeProxyInfo`
func SenseKubeProxyInfo(ctx context.Context) (*KubeProxyInfo, error) {
	ret := KubeProxyInfo{}

	// Get process
	proc, err := sensorUtils.LocateProcessByExecSuffix(kubeProxyExe)
	if err != nil {
		return &ret, fmt.Errorf("failed to locate kube-proxy process: %w", err)
	}

	// kubeconfig
	kubeConfigPath, ok := proc.GetArg(kubeConfigArgName)
	if ok {
		ret.KubeConfigFile = makeContaineredFileInfoVerbose(ctx, proc, kubeConfigPath, false,
			helpers.String("in", "SenseKubeProxyInfo"),
		)
	}

	// cmd line
	ret.CmdLine = proc.RawCmd()

	return &ret, nil
}
