package hostsensormanager

import (
	"context"

	"github.com/kubescape/go-logger"
)

// CNIInfoSensor implements the Sensor interface for CNI info data
type CNIInfoSensor struct {
	nodeName string
}

// NewCNIInfoSensor creates a new CNI info sensor
func NewCNIInfoSensor(nodeName string) *CNIInfoSensor {
	return &CNIInfoSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *CNIInfoSensor) GetKind() string {
	return "CNIInfo"
}

// Sense collects the CNI info data from the host
func (s *CNIInfoSensor) Sense() (interface{}, error) {
	ctx := context.Background()
	ret := CNIInfoSpec{
		NodeName: s.nodeName,
	}

	// Simplified CNI config path collection for now
	// host-scanner uses Kubelet process to find CNI path, but we can try some defaults
	cniConfigDirs := []string{"/etc/cni/net.d"}

	for _, dir := range cniConfigDirs {
		infos, err := makeHostDirFilesInfoVerbose(ctx, dir, true, 0)
		if err == nil {
			ret.CNIConfigFiles = append(ret.CNIConfigFiles, infos...)
		}
	}

	ret.CNINames = s.getCNINames()

	return &ret, nil
}

func (s *CNIInfoSensor) getCNINames() []string {
	var CNIs []string
	supportedCNIs := []struct {
		name          string
		processSuffix string
	}{
		{"aws", "aws-k8s-agent"},
		{"Calico", "calico-node"},
		{"Flannel", "flanneld"},
		{"Cilium", "cilium-agent"},
		{"WeaveNet", "weave-net"},
		{"Kindnet", "kindnetd"},
		{"Multus", "multus"},
	}

	for _, cni := range supportedCNIs {
		p, _ := LocateProcessByExecSuffix(cni.processSuffix)
		if p != nil {
			CNIs = append(CNIs, cni.name)
		}
	}

	if len(CNIs) == 0 {
		logger.L().Debug("no CNI found")
	}

	return CNIs
}
