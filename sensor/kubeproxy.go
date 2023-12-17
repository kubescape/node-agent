package sensor

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger/helpers"
	ds "github.com/kubescape/node-agent/sensor/datastructures"
	"github.com/kubescape/node-agent/sensor/internal/utils"
)

const (
	kubeProxyExe = "kube-proxy"
)

// KubeProxyInfo holds information about kube-proxy process
type KubeProxyInfo struct {
	// Information about the kubeconfig file of kube-proxy
	KubeConfigFile *ds.FileInfo `json:"kubeConfigFile,omitempty"`

	// Raw cmd line of kubelet process
	CmdLine string `json:"cmdLine"`
}

// SenseKubeProxyInfo return `KubeProxyInfo`
func SenseKubeProxyInfo(ctx context.Context) (*KubeProxyInfo, error) {
	ret := KubeProxyInfo{}

	// Get process
	proc, err := utils.LocateProcessByExecSuffix(kubeProxyExe)
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
