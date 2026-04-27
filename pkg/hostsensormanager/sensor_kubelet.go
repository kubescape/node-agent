package hostsensormanager

import (
	"context"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/hostsensor"
	"sigs.k8s.io/yaml"
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

var kubeletServiceFilePaths = []string{
	"/etc/systemd/system/kubelet.service",
	"/usr/lib/systemd/system/kubelet.service",
	"/lib/systemd/system/kubelet.service",
}

const kubeletServiceDropInDir = "/etc/systemd/system/kubelet.service.d"

// kubeletConfigYAML is a minimal subset of KubeletConfiguration for CA file extraction.
type kubeletConfigYAML struct {
	Authentication struct {
		X509 struct {
			ClientCAFile string `json:"clientCAFile"`
		} `json:"x509"`
	} `json:"authentication"`
}

// extractClientCAFromKubeletConfig parses kubelet config YAML and returns the clientCAFile path.
func extractClientCAFromKubeletConfig(content []byte) (string, error) {
	var cfg kubeletConfigYAML
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse kubelet config: %w", err)
	}
	return cfg.Authentication.X509.ClientCAFile, nil
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
	return string(hostsensor.KubeletInfo)
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *KubeletInfoSensor) GetPluralKind() string {
	return hostsensor.MapResourceToPlural(hostsensor.KubeletInfo)
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

	// Client CA: check cmdLine first, then fall back to kubelet config YAML
	if caFilePath, ok := kubeletProcess.GetArg(kubeletClientCAArgName); ok {
		ret.ClientCAFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, caFilePath, false, helpers.String("in", "SenseKubeletInfo"))
	} else if ret.ConfigFile != nil && len(ret.ConfigFile.Content) > 0 {
		if caFilePath, err := extractClientCAFromKubeletConfig(ret.ConfigFile.Content); err != nil {
			logger.L().Debug("failed to extract clientCAFile from kubelet config", helpers.String("in", "SenseKubeletInfo"), helpers.Error(err))
		} else if caFilePath != "" {
			ret.ClientCAFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, caFilePath, false, helpers.String("in", "SenseKubeletInfo"))
		}
	}

	ret.CmdLine = kubeletProcess.RawCmd()

	// Service files: main unit file and drop-in directory
	for _, svcPath := range kubeletServiceFilePaths {
		if fi := makeHostFileInfoVerbose(ctx, svcPath, false); fi != nil {
			ret.ServiceFiles = append(ret.ServiceFiles, *fi)
			break
		}
	}
	if dropIns, err := makeHostDirFilesInfoVerbose(ctx, kubeletServiceDropInDir, false, 0); err == nil {
		for _, fi := range dropIns {
			ret.ServiceFiles = append(ret.ServiceFiles, *fi)
		}
	}

	return &ret, nil
}
