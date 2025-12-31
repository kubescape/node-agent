package hostsensormanager

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	etcDirName          = "/etc"
	osReleaseFileSuffix = "os-release"
	hostFSPrefix        = "/host_fs" // Mount point for host filesystem
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
	return "OsReleaseFile"
}

// Sense collects the OS release data from the host
func (s *OsReleaseSensor) Sense() (interface{}, error) {
	osFileName, err := s.getOsReleaseFile()
	if err != nil {
		return nil, fmt.Errorf("failed to find os-release file: %w", err)
	}

	content, err := s.readFileOnHostFileSystem(path.Join(etcDirName, osFileName))
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
	hostEtcDir := s.hostPath(etcDirName)
	etcDir, err := os.Open(hostEtcDir)
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
	return "", fmt.Errorf("os-release file not found in %s", hostEtcDir)
}

// hostPath converts a path to the host filesystem path
func (s *OsReleaseSensor) hostPath(p string) string {
	return path.Join(hostFSPrefix, p)
}

// readFileOnHostFileSystem reads a file from the host filesystem
func (s *OsReleaseSensor) readFileOnHostFileSystem(filePath string) ([]byte, error) {
	hostPath := s.hostPath(filePath)
	content, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", hostPath, err)
	}
	return content, nil
}
