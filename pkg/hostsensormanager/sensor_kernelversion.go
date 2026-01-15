package hostsensormanager

import (
	"fmt"
	"path"
)

const (
	kernelVersionFileName = "version"
)

// KernelVersionSensor implements the Sensor interface for kernel version data
type KernelVersionSensor struct {
	nodeName string
}

// NewKernelVersionSensor creates a new kernel version sensor
func NewKernelVersionSensor(nodeName string) *KernelVersionSensor {
	return &KernelVersionSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *KernelVersionSensor) GetKind() string {
	return "KernelVersion"
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *KernelVersionSensor) GetPluralKind() string {
	return "kernelversions"
}

// Sense collects the kernel version data from the host
func (s *KernelVersionSensor) Sense() (interface{}, error) {
	content, err := readFileOnHostFileSystem(path.Join(procDirName, kernelVersionFileName))
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel version file: %w", err)
	}

	return &KernelVersionSpec{
		Content:  string(content),
		NodeName: s.nodeName,
	}, nil
}
