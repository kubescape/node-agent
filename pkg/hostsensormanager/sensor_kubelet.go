package hostsensormanager

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger/helpers"
)

const (
	kubeletProcessSuffix   = "/kubelet"
	kubeletConfigArgName   = "--config"
	kubeletClientCAArgName = "--client-ca-file"
	kubeConfigArgName      = "--kubeconfig"
)

var kubeletConfigDefaultPathList = []string{
	"/var/lib/kubelet/config.yaml",
	"/etc/kubernetes/kubelet/kubelet-config.json",
}

var kubeletKubeConfigDefaultPathList = []string{
	"/etc/kubernetes/kubelet.conf",
	"/var/lib/kubelet/kubeconfig",
}

// KubeletInfoSensor implements the Sensor interface for kubelet info data
type KubeletInfoSensor struct {
	nodeName string
}

// NewKubeletInfoSensor creates a new kubelet info sensor
func NewKubeletInfoSensor(nodeName string) *KubeletInfoSensor {
	return &KubeletInfoSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *KubeletInfoSensor) GetKind() string {
	return "KubeletInfo"
}

// Sense collects the kubelet info data from the host
func (s *KubeletInfoSensor) Sense() (interface{}, error) {
	ctx := context.Background()
	ret := KubeletInfoSpec{
		NodeName: s.nodeName,
	}

	kubeletProcess, err := LocateProcessByExecSuffix(kubeletProcessSuffix)
	if err != nil {
		return &ret, fmt.Errorf("failed to locate kubelet process: %w", err)
	}

	// Config file
	if pConfigPath, ok := kubeletProcess.GetArg(kubeletConfigArgName); ok {
		ret.ConfigFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, pConfigPath, true, helpers.String("in", "SenseKubeletInfo"))
	} else {
		ret.ConfigFile = makeContaineredFileInfoFromListVerbose(ctx, kubeletProcess, kubeletConfigDefaultPathList, true, helpers.String("in", "SenseKubeletInfo"))
	}

	// Kubeconfig
	if pKubeConfigPath, ok := kubeletProcess.GetArg(kubeConfigArgName); ok {
		ret.KubeConfigFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, pKubeConfigPath, true, helpers.String("in", "SenseKubeletInfo"))
	} else {
		ret.KubeConfigFile = makeContaineredFileInfoFromListVerbose(ctx, kubeletProcess, kubeletKubeConfigDefaultPathList, true, helpers.String("in", "SenseKubeletInfo"))
	}

	// Client CA
	if caFilePath, ok := kubeletProcess.GetArg(kubeletClientCAArgName); ok {
		ret.ClientCAFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, caFilePath, false, helpers.String("in", "SenseKubeletInfo"))
	}

	ret.CmdLine = kubeletProcess.RawCmd()

	return &ret, nil
}
