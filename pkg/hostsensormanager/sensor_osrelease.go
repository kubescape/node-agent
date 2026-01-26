package hostsensormanager

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/hostsensor"
)

const (
	etcDirName          = "/etc"
	osReleaseFileSuffix = "os-release"
)

// OsReleaseSensor implements the Sensor interface for OS release data
type OsReleaseSensor struct {
	nodeName string
}

// NewOsReleaseSensor creates a new OS release sensor
func NewOsReleaseSensor(nodeName string) *OsReleaseSensor {
	return &OsReleaseSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *OsReleaseSensor) GetKind() string {
	return string(hostsensor.OsReleaseFile)
}

// GetPluralKind returns the plural and lowercase form of CRD kind for this sensor
func (s *OsReleaseSensor) GetPluralKind() string {
	return hostsensor.MapResourceToPlural(hostsensor.OsReleaseFile)
}

// Sense collects the OS release data from the host
func (s *OsReleaseSensor) Sense() (interface{}, error) {
	osFileName, err := s.getOsReleaseFile()
	if err != nil {
		return nil, fmt.Errorf("failed to find os-release file: %w", err)
	}

	content, err := readFileOnHostFileSystem(path.Join(etcDirName, osFileName))
	if err != nil {
		return nil, fmt.Errorf("failed to read os-release file: %w", err)
	}

	return &OsReleaseFileSpec{
		Content:  string(content),
		NodeName: s.nodeName,
	}, nil
}

// getOsReleaseFile finds the OS release file in /etc
func (s *OsReleaseSensor) getOsReleaseFile() (string, error) {
	hEtcDir := hostPath(etcDirName)
	etcDir, err := os.Open(hEtcDir)
	if err != nil {
		return "", fmt.Errorf("failed to open etc dir: %w", err)
	}
	defer etcDir.Close()

	var etcSons []string
	for etcSons, err = etcDir.Readdirnames(100); err == nil; etcSons, err = etcDir.Readdirnames(100) {
		for idx := range etcSons {
			if strings.HasSuffix(etcSons[idx], osReleaseFileSuffix) {
				logger.L().Debug("os release file found", helpers.String("filename", etcSons[idx]))
				return etcSons[idx], nil
			}
		}
	}
	return "", fmt.Errorf("os-release file not found in %s", hEtcDir)
}
