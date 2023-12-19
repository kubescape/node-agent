package sensor

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	// ds "github.com/kubescape/node-agent/sensor/datastructures"
	ds "github.com/kubescape/host-scanner/sensor/datastructures"
	// "github.com/kubescape/node-agent/sensor/internal/utils"
	hostUtils "github.com/kubescape/host-scanner/sensor/internal/utils"
)

// KubeProxyInfo holds information about kube-proxy process
type CNIInfo struct {
	CNIConfigFiles []*ds.FileInfo `json:"CNIConfigFiles,omitempty"`

	// The name of the running CNI
	CNINames []string `json:"CNINames,omitempty"`
}

// SenseCNIInfo return `CNIInfo`
func SenseCNIInfo(ctx context.Context) (*CNIInfo, error) {
	var err error
	ret := CNIInfo{}

	// make cni config files
	CNIConfigInfo, err := makeCNIConfigFilesInfo(ctx)

	if err != nil {
		logger.L().Ctx(ctx).Warning("SenseCNIInfo", helpers.Error(err))
	} else {
		ret.CNIConfigFiles = CNIConfigInfo
	}

	// get CNI name
	ret.CNINames = getCNINames(ctx)

	return &ret, nil
}

// makeCNIConfigFilesInfo - returns a list of FileInfos of cni config files.
func makeCNIConfigFilesInfo(ctx context.Context) ([]*ds.FileInfo, error) {
	// *** Start handling CNI Files
	kubeletProc, err := LocateKubeletProcess()
	if err != nil {
		return nil, err
	}

	CNIConfigDir := hostUtils.GetCNIConfigPath(ctx, kubeletProc)

	if CNIConfigDir == "" {
		return nil, fmt.Errorf("no CNI Config dir found in getCNIConfigPath")
	}

	//Getting CNI config files
	CNIConfigInfo, err := makeHostDirFilesInfoVerbose(ctx, CNIConfigDir, true, nil, 0)

	if err != nil {
		return nil, fmt.Errorf("failed to makeHostDirFilesInfo for CNIConfigDir %s: %w", CNIConfigDir, err)
	}

	if len(CNIConfigInfo) == 0 {
		logger.L().Debug("SenseCNIInfo - no cni config files were found.",
			helpers.String("path", CNIConfigDir))
	}

	return CNIConfigInfo, nil
}

// getCNIName - looking for CNI process and return CNI name, or empty if not found.
func getCNINames(ctx context.Context) []string {
	var CNIs []string
	supportedCNIs := []struct {
		name          string
		processSuffix string
	}{
		{"aws", "aws-k8s-agent"}, // aws VPC CNI agent
		// 'canal' CNI "sets up Calico to handle policy management and Flannel to manage the network itself". Therefore, we will first
		// check "calico" (which supports network policies and indicates for either 'canal' or 'calico') and then flannel.
		{"Calico", "calico-node"},
		{"Flannel", "flanneld"},
		{"Cilium", "cilium-agent"},
		{"WeaveNet", "weave-net"},
		{"Kindnet", "kindnetd"},
		{"Multus", "multus"},
	}

	for _, cni := range supportedCNIs {
		p, _ := hostUtils.LocateProcessByExecSuffix(cni.processSuffix)

		if p != nil {
			logger.L().Debug("CNI process found", helpers.String("name", cni.name))
			CNIs = append(CNIs, cni.name)
		}
	}

	if len(CNIs) == 0 {
		logger.L().Warning("No CNI found")
	}

	return CNIs
}
