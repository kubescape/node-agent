package sensor

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	ds "github.com/kubescape/node-agent/sensor/datastructures"
	"github.com/kubescape/node-agent/sensor/internal/utils"
	"sigs.k8s.io/yaml"
)

const (
	procDirName            = "/proc"
	kubeletProcessSuffix   = "/kubelet"
	kubeletConfigArgName   = "--config"
	kubeletClientCAArgName = "--client-ca-file"
)

// default paths
var kubeletConfigDefaultPathList = []string{
	"/var/lib/kubelet/config.yaml",                // default kubelet config file path
	"/etc/kubernetes/kubelet/kubelet-config.json", // default EKS config file path
}
var kubeletKubeConfigDefaultPathList = []string{
	"/etc/kubernetes/kubelet.conf", // default kubelet kube config file path
	"/var/lib/kubelet/kubeconfig",  // default EKS kubeconfig file path
}

// KubeletInfo holds information about kubelet
type KubeletInfo struct {
	// ServiceFile is a list of files used to configure the kubelet service.
	// Most of the times it will be a single file, under /etc/systemd/system/kubelet.service.d.
	ServiceFiles []ds.FileInfo `json:"serviceFiles,omitempty"`

	// Information about kubelete config file
	ConfigFile *ds.FileInfo `json:"configFile,omitempty"`

	// Information about the kubeconfig file of kubelet
	KubeConfigFile *ds.FileInfo `json:"kubeConfigFile,omitempty"`

	// Information about the client ca file of kubelet (if exist)
	ClientCAFile *ds.FileInfo `json:"clientCAFile,omitempty"`

	// Raw cmd line of kubelet process
	CmdLine string `json:"cmdLine"`
}

func LocateKubeletProcess() (*utils.ProcessDetails, error) {
	return utils.LocateProcessByExecSuffix(kubeletProcessSuffix)
}

func ReadKubeletConfig(kubeletConfArgs string) ([]byte, error) {
	conte, err := utils.ReadFileOnHostFileSystem(kubeletConfArgs)
	logger.L().Debug("raw content", helpers.String("cont", string(conte)))
	return conte, err
}

func makeKubeletServiceFilesInfo(ctx context.Context, pid int) []ds.FileInfo {
	files, err := utils.GetKubeletServiceFiles(pid)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to getKubeletServiceFiles", helpers.Error(err))
		return nil
	}

	serviceFiles := []ds.FileInfo{}
	for _, file := range files {
		info := makeHostFileInfoVerbose(ctx, file, false, helpers.String("in", "makeProcessInfoVerbose"))
		if info != nil {
			serviceFiles = append(serviceFiles, *info)
		}
	}

	if len(serviceFiles) == 0 {
		return nil
	}

	return serviceFiles
}

// SenseKubeletInfo return varius information about the kubelet service
func SenseKubeletInfo(ctx context.Context) (*KubeletInfo, error) {
	ret := KubeletInfo{}

	kubeletProcess, err := LocateKubeletProcess()
	if err != nil {
		return &ret, fmt.Errorf("failed to Locate kubelet process: %w", err)
	}

	// Serivce files
	ret.ServiceFiles = makeKubeletServiceFilesInfo(ctx, int(kubeletProcess.PID))

	pConfigPath, ok := kubeletProcess.GetArg(kubeletConfigArgName)
	if ok {
		ret.ConfigFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, pConfigPath, true,
			helpers.String("in", "SenseKubeletInfo"),
		)
	} else {
		ret.ConfigFile = makeContaineredFileInfoFromListVerbose(ctx, kubeletProcess, kubeletConfigDefaultPathList, true,
			helpers.String("in", "SenseKubeletInfo"),
		)
	}

	pKubeConfigPath, ok := kubeletProcess.GetArg(kubeConfigArgName)
	if ok {
		ret.KubeConfigFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, pKubeConfigPath, true,
			helpers.String("in", "SenseKubeletInfo"),
		)
	} else {
		ret.KubeConfigFile = makeContaineredFileInfoFromListVerbose(ctx, kubeletProcess, kubeletKubeConfigDefaultPathList, true,
			helpers.String("in", "SenseKubeletInfo"),
		)
	}

	// Kubelet client ca certificate
	caFilePath, ok := kubeletProcess.GetArg(kubeletClientCAArgName)
	if !ok && ret.ConfigFile != nil && ret.ConfigFile.Content != nil {
		logger.L().Debug("extracting kubelet client ca certificate from config")
		extracted, err := kubeletExtractCAFileFromConf(ret.ConfigFile.Content)
		if err == nil {
			caFilePath = extracted
		}
	}
	if caFilePath != "" {
		ret.ClientCAFile = makeContaineredFileInfoVerbose(ctx, kubeletProcess, caFilePath, false,
			helpers.String("in", "SenseKubeletInfo"),
		)
	}

	// Cmd line
	ret.CmdLine = kubeletProcess.RawCmd()

	return &ret, nil
}

// kubeletExtractCAFileFromConf extract the client ca file path from kubelet config
func kubeletExtractCAFileFromConf(content []byte) (string, error) {
	var kubeletConfig struct {
		Authentication struct {
			X509 struct {
				ClientCAFile string
			}
		}
	}

	err := yaml.Unmarshal(content, &kubeletConfig)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal kubelet config: %w", err)
	}

	return kubeletConfig.Authentication.X509.ClientCAFile, nil
}
