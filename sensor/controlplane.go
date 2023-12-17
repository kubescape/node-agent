package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"gopkg.in/yaml.v3"

	ds "github.com/kubescape/node-agent/sensor/datastructures"
	"github.com/kubescape/node-agent/sensor/internal/utils"
)

const (
	apiServerExe                   = "/kube-apiserver"
	controllerManagerExe           = "/kube-controller-manager"
	schedulerExe                   = "/kube-scheduler"
	etcdExe                        = "/etcd"
	etcdDataDirArg                 = "--data-dir"
	apiEncryptionProviderConfigArg = "--encryption-provider-config"
	auditPolicyFileArg             = "--audit-policy-file"

	// Default files paths according to https://workbench.cisecurity.org/benchmarks/8973/sections/1126652
	apiServerSpecsPath          = "/etc/kubernetes/manifests/kube-apiserver.yaml"
	controllerManagerSpecsPath  = "/etc/kubernetes/manifests/kube-controller-manager.yaml"
	controllerManagerConfigPath = "/etc/kubernetes/controller-manager.conf"
	schedulerSpecsPath          = "/etc/kubernetes/manifests/kube-scheduler.yaml"
	schedulerConfigPath         = "/etc/kubernetes/scheduler.conf"
	etcdConfigPath              = "/etc/kubernetes/manifests/etcd.yaml"
	adminConfigPath             = "/etc/kubernetes/admin.conf"
	pkiDir                      = "/etc/kubernetes/pki"

	// TODO: cni
)

var (
	ErrDataDirNotFound = errors.New("failed to find etcd data-dir")
)

// KubeProxyInfo holds information about kube-proxy process
type ControlPlaneInfo struct {
	APIServerInfo         *ApiServerInfo  `json:"APIServerInfo,omitempty"`
	ControllerManagerInfo *K8sProcessInfo `json:"controllerManagerInfo,omitempty"`
	SchedulerInfo         *K8sProcessInfo `json:"schedulerInfo,omitempty"`
	EtcdConfigFile        *ds.FileInfo    `json:"etcdConfigFile,omitempty"`
	EtcdDataDir           *ds.FileInfo    `json:"etcdDataDir,omitempty"`
	AdminConfigFile       *ds.FileInfo    `json:"adminConfigFile,omitempty"`
	PKIDIr                *ds.FileInfo    `json:"PKIDir,omitempty"`
	PKIFiles              []*ds.FileInfo  `json:"PKIFiles,omitempty"`
}

// K8sProcessInfo holds information about a k8s process
type K8sProcessInfo struct {
	// Information about the process specs file (if relevant)
	SpecsFile *ds.FileInfo `json:"specsFile,omitempty"`

	// Information about the process config file (if relevant)
	ConfigFile *ds.FileInfo `json:"configFile,omitempty"`

	// Information about the process kubeconfig file (if relevant)
	KubeConfigFile *ds.FileInfo `json:"kubeConfigFile,omitempty"`

	// Information about the process client ca file (if relevant)
	ClientCAFile *ds.FileInfo `json:"clientCAFile,omitempty"`

	// Raw cmd line of the process
	CmdLine string `json:"cmdLine"`
}

type ApiServerInfo struct {
	EncryptionProviderConfigFile *ds.FileInfo `json:"encryptionProviderConfigFile,omitempty"`
	AuditPolicyFile              *ds.FileInfo `json:"auditPolicyFile,omitempty"`
	*K8sProcessInfo              `json:",inline"`
}

// getEtcdDataDir find the `data-dir` path of etcd k8s component
func getEtcdDataDir() (string, error) {

	proc, err := utils.LocateProcessByExecSuffix(etcdExe)
	if err != nil {
		return "", fmt.Errorf("failed to locate etcd process: %w", err)
	}

	dataDir, ok := proc.GetArg(etcdDataDirArg)
	if !ok || dataDir == "" {
		return "", ErrDataDirNotFound
	}

	return dataDir, nil
}

func makeProcessInfoVerbose(ctx context.Context, p *utils.ProcessDetails, specsPath, configPath, kubeConfigPath, clientCaPath string) *K8sProcessInfo {
	ret := K8sProcessInfo{}

	// init files
	files := []struct {
		data **ds.FileInfo
		path string
		file string
	}{
		{&ret.SpecsFile, specsPath, "specs"},
		{&ret.ConfigFile, configPath, "config"},
		{&ret.KubeConfigFile, kubeConfigPath, "kubeconfig"},
		{&ret.ClientCAFile, clientCaPath, "client ca certificate"},
	}

	// get data
	for i := range files {
		file := &files[i]
		if file.path == "" {
			continue
		}

		*file.data = makeHostFileInfoVerbose(ctx, file.path, false,
			helpers.String("in", "makeProcessInfoVerbose"),
			helpers.String("path", file.path),
		)
	}

	if p != nil {
		ret.CmdLine = p.RawCmd()
	}

	// Return `nil` if wasn't able to find any data
	if ret == (K8sProcessInfo{}) {
		return nil
	}

	return &ret
}

// makeAPIserverEncryptionProviderConfigFile returns a ds.FileInfo object for the encryption provider config file of the API server. Required for https://workbench.cisecurity.org/sections/1126663/recommendations/1838675
func makeAPIserverEncryptionProviderConfigFile(ctx context.Context, p *utils.ProcessDetails) *ds.FileInfo {
	encryptionProviderConfigPath, ok := p.GetArg(apiEncryptionProviderConfigArg)
	if !ok {
		logger.L().Ctx(ctx).Warning("failed to find encryption provider config path", helpers.String("in", "makeAPIserverEncryptionProviderConfigFile"))
		return nil
	}

	fi, err := utils.MakeContaineredFileInfo(ctx, p, encryptionProviderConfigPath, true)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to create encryption provider config file info", helpers.Error(err))
		return nil
	}

	// remove sensitive data
	data := map[string]interface{}{}

	if errYaml := yaml.Unmarshal(fi.Content, &data); errYaml != nil {
		if errJson := json.Unmarshal(fi.Content, &data); errJson != nil {
			logger.L().Ctx(ctx).Warning("failed to unmarshal encryption provider config file", helpers.Error(errJson), helpers.Error(errYaml))
			return nil
		}
	}

	removeEncryptionProviderConfigSecrets(data)

	// marshal back to yaml
	fi.Content, err = yaml.Marshal(data)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to marshal encryption provider config file", helpers.Error(err))
		return nil
	}

	return fi
}

func removeEncryptionProviderConfigSecrets(data map[string]interface{}) {
	resources, ok := data["resources"].([]interface{})
	if !ok {
		return
	}

	for i := range resources {
		resource, ok := resources[i].(map[string]interface{})
		if !ok {
			continue
		}

		providers, ok := resource["providers"].([]interface{})
		if !ok {
			continue
		}

		for j := range providers {
			provider, ok := providers[j].(map[string]interface{})
			if !ok {
				continue
			}

			for key := range provider {
				object, ok := provider[key].(map[string]interface{})
				if !ok {
					continue
				}
				keys, ok := object["keys"].([]interface{})
				if !ok {
					continue
				}
				for k := range keys {
					key, ok := keys[k].(map[string]interface{})
					if !ok {
						continue
					}
					key["secret"] = "<REDACTED>"
					keys[k] = key
				}
				object["keys"] = keys
				provider[key] = object
			}
			providers[j] = provider
		}
		resource["providers"] = providers
		resources[i] = resource
	}
	data["resources"] = resources
}

// makeAPIserverAuditPolicyFile returns a ds.FileInfo object for an audit policy file of the API server. Required for https://workbench.cisecurity.org/sections/1126663/recommendations/1838675
func makeAPIserverAuditPolicyFile(ctx context.Context, p *utils.ProcessDetails) *ds.FileInfo {
	auditPolicyFilePath, ok := p.GetArg(auditPolicyFileArg)
	if !ok {
		logger.L().Info("audit-policy-file argument was not set ", helpers.String("in", "makeAPIserverAuditPolicyFile"))
		return nil
	}

	return makeContaineredFileInfoVerbose(ctx, p, auditPolicyFilePath, true,
		helpers.String("in", "makeAPIserverAuditPolicyFile"),
	)
}

// SenseControlPlaneInfo return `ControlPlaneInfo`
func SenseControlPlaneInfo(ctx context.Context) (*ControlPlaneInfo, error) {
	var err error
	ret := ControlPlaneInfo{}

	debugInfo := helpers.String("in", "SenseControlPlaneInfo")

	apiProc, err := utils.LocateProcessByExecSuffix(apiServerExe)
	if err == nil {
		ret.APIServerInfo = &ApiServerInfo{}
		ret.APIServerInfo.K8sProcessInfo = makeProcessInfoVerbose(ctx, apiProc, apiServerSpecsPath, "", "", "")
		ret.APIServerInfo.EncryptionProviderConfigFile = makeAPIserverEncryptionProviderConfigFile(ctx, apiProc)
		ret.APIServerInfo.AuditPolicyFile = makeAPIserverAuditPolicyFile(ctx, apiProc)
	} else {
		logger.L().Ctx(ctx).Warning("SenseControlPlaneInfo", helpers.Error(err))
	}

	controllerMangerProc, err := utils.LocateProcessByExecSuffix(controllerManagerExe)
	if err == nil {
		ret.ControllerManagerInfo = makeProcessInfoVerbose(ctx, controllerMangerProc, controllerManagerSpecsPath, controllerManagerConfigPath, "", "")
	} else {
		logger.L().Ctx(ctx).Warning("SenseControlPlaneInfo", helpers.Error(err))
	}

	SchedulerProc, err := utils.LocateProcessByExecSuffix(schedulerExe)
	if err == nil {
		ret.SchedulerInfo = makeProcessInfoVerbose(ctx, SchedulerProc, schedulerSpecsPath, schedulerConfigPath, "", "")
	} else {
		logger.L().Ctx(ctx).Warning("SenseControlPlaneInfo", helpers.Error(err))
	}

	// EtcdConfigFile
	ret.EtcdConfigFile = makeHostFileInfoVerbose(ctx, etcdConfigPath,
		false,
		debugInfo,
		helpers.String("component", "EtcdConfigFile"),
	)

	// AdminConfigFile
	ret.AdminConfigFile = makeHostFileInfoVerbose(ctx, adminConfigPath,
		false,
		debugInfo,
		helpers.String("component", "AdminConfigFile"),
	)

	// PKIDIr
	ret.PKIDIr = makeHostFileInfoVerbose(ctx, pkiDir,
		false,
		debugInfo,
		helpers.String("component", "PKIDIr"),
	)

	// PKIFiles
	ret.PKIFiles, err = makeHostDirFilesInfoVerbose(ctx, pkiDir, true, nil, 0)
	if err != nil {
		logger.L().Ctx(ctx).Warning("SenseControlPlaneInfo failed to get PKIFiles info", helpers.Error(err))
	}

	// etcd data-dir
	etcdDataDir, err := getEtcdDataDir()
	if err != nil {
		logger.L().Ctx(ctx).Warning("SenseControlPlaneInfo", helpers.Error(ErrDataDirNotFound))
	} else {
		ret.EtcdDataDir = makeHostFileInfoVerbose(ctx, etcdDataDir,
			false,
			debugInfo,
			helpers.String("component", "EtcdDataDir"),
		)
	}

	// If wasn't able to find any data - this is not a control plane
	if ret.APIServerInfo == nil &&
		ret.ControllerManagerInfo == nil &&
		ret.SchedulerInfo == nil &&
		ret.EtcdConfigFile == nil &&
		ret.EtcdDataDir == nil &&
		ret.AdminConfigFile == nil {
		return nil, &SenseError{
			Massage:  "not a control plane node",
			Function: "SenseControlPlaneInfo",
			Code:     http.StatusOK,
		}
	}

	return &ret, nil
}
