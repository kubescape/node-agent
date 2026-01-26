package hostsensormanager

import (
	"context"

	"github.com/kubescape/k8s-interface/hostsensor"
)

const (
	apiServerExe         = "/kube-apiserver"
	controllerManagerExe = "/kube-controller-manager"
	schedulerExe         = "/kube-scheduler"
	etcdExe              = "/etcd"
	etcdDataDirArg       = "--data-dir"
	auditPolicyFileArg   = "--audit-policy-file"

	apiServerSpecsPath         = "/etc/kubernetes/manifests/kube-apiserver.yaml"
	controllerManagerSpecsPath = "/etc/kubernetes/manifests/kube-controller-manager.yaml"
	schedulerSpecsPath         = "/etc/kubernetes/manifests/kube-scheduler.yaml"
	etcdConfigPath             = "/etc/kubernetes/manifests/etcd.yaml"
	adminConfigPath            = "/etc/kubernetes/admin.conf"
	pkiDir                     = "/etc/kubernetes/pki"
)

// ControlPlaneInfoSensor implements the Sensor interface for control plane info data
type ControlPlaneInfoSensor struct {
	nodeName string
}

// NewControlPlaneInfoSensor creates a new control plane info sensor
func NewControlPlaneInfoSensor(nodeName string) *ControlPlaneInfoSensor {
	return &ControlPlaneInfoSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *ControlPlaneInfoSensor) GetKind() string {
	return string(hostsensor.ControlPlaneInfo)
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *ControlPlaneInfoSensor) GetPluralKind() string {
	return hostsensor.MapResourceToPlural(hostsensor.ControlPlaneInfo)
}

// Sense collects the control plane info data from the host
func (s *ControlPlaneInfoSensor) Sense() (interface{}, error) {
	ctx := context.Background()
	ret := ControlPlaneInfoSpec{
		NodeName: s.nodeName,
	}

	// API Server
	if proc, err := LocateProcessByExecSuffix(apiServerExe); err == nil {
		ret.APIServerInfo = &ApiServerInfo{
			ProcessInfo: ProcessInfo{
				CmdLine:   proc.RawCmd(),
				SpecsFile: makeHostFileInfoVerbose(ctx, apiServerSpecsPath, false),
			},
			AuditPolicyFile: makeContaineredFileInfoVerbose(ctx, proc, auditPolicyFileArg, false),
		}
	}

	// Controller Manager
	if proc, err := LocateProcessByExecSuffix(controllerManagerExe); err == nil {
		ret.ControllerManagerInfo = &ProcessInfo{
			CmdLine:   proc.RawCmd(),
			SpecsFile: makeHostFileInfoVerbose(ctx, controllerManagerSpecsPath, false),
		}
	}

	// Scheduler
	if proc, err := LocateProcessByExecSuffix(schedulerExe); err == nil {
		ret.SchedulerInfo = &ProcessInfo{
			CmdLine:   proc.RawCmd(),
			SpecsFile: makeHostFileInfoVerbose(ctx, schedulerSpecsPath, false),
		}
	}

	// Other configs
	ret.EtcdConfigFile = makeHostFileInfoVerbose(ctx, etcdConfigPath, false)
	ret.AdminConfigFile = makeHostFileInfoVerbose(ctx, adminConfigPath, false)
	ret.PKIDir = makeHostFileInfoVerbose(ctx, pkiDir, false)

	// PKI files
	pkiFiles, _ := makeHostDirFilesInfoVerbose(ctx, pkiDir, true, 0)
	ret.PKIFiles = pkiFiles

	return &ret, nil
}
