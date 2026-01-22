package hostsensormanager

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/hostsensor"
)

const (
	kubeProxyExe = "kube-proxy"
)

// KubeProxyInfoSensor implements the Sensor interface for kube-proxy info data
type KubeProxyInfoSensor struct {
	nodeName string
}

// NewKubeProxyInfoSensor creates a new kube-proxy info sensor
func NewKubeProxyInfoSensor(nodeName string) *KubeProxyInfoSensor {
	return &KubeProxyInfoSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *KubeProxyInfoSensor) GetKind() string {
	return string(hostsensor.KubeProxyInfo)
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *KubeProxyInfoSensor) GetPluralKind() string {
	return hostsensor.MapResourceToPlural(hostsensor.KubeProxyInfo)
}

// Sense collects the kube-proxy info data from the host
func (s *KubeProxyInfoSensor) Sense() (interface{}, error) {
	ctx := context.Background()
	ret := KubeProxyInfoSpec{
		NodeName: s.nodeName,
	}

	proc, err := LocateProcessByExecSuffix(kubeProxyExe)
	if err != nil {
		return &ret, fmt.Errorf("failed to locate kube-proxy process: %w", err)
	}

	if kubeConfigPath, ok := proc.GetArg(kubeConfigArgName); ok {
		ret.KubeConfigFile = makeContaineredFileInfoVerbose(ctx, proc, kubeConfigPath, false, helpers.String("in", "SenseKubeProxyInfo"))
	}

	ret.CmdLine = proc.RawCmd()

	return &ret, nil
}
