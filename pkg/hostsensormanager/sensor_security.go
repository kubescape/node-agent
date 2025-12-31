package hostsensormanager

import (
	"os"
)

const (
	appArmorProfilesFileName = "/sys/kernel/security/apparmor/profiles"
	seLinuxConfigFileName    = "/etc/selinux/semanage.conf"
)

// LinuxSecurityHardeningSensor implements the Sensor interface for security hardening data
type LinuxSecurityHardeningSensor struct {
	nodeName string
}

// NewLinuxSecurityHardeningSensor creates a new security hardening sensor
func NewLinuxSecurityHardeningSensor(nodeName string) *LinuxSecurityHardeningSensor {
	return &LinuxSecurityHardeningSensor{
		nodeName: nodeName,
	}
}

// GetKind returns the CRD kind for this sensor
func (s *LinuxSecurityHardeningSensor) GetKind() string {
	return "LinuxSecurityHardening"
}

// Sense collects the security hardening data from the host
func (s *LinuxSecurityHardeningSensor) Sense() (interface{}, error) {
	return &LinuxSecurityHardeningSpec{
		AppArmor: s.getAppArmorStatus(),
		SeLinux:  s.getSELinuxStatus(),
		NodeName: s.nodeName,
	}, nil
}

func (s *LinuxSecurityHardeningSensor) getAppArmorStatus() string {
	statusStr := "unloaded"
	hAppArmorProfilesFileName := hostPath(appArmorProfilesFileName)
	profFile, err := os.Open(hAppArmorProfilesFileName)
	if err == nil {
		defer profFile.Close()
		statusStr = "stopped"
		content, err := readFileOnHostFileSystem(appArmorProfilesFileName)
		if err == nil && len(content) > 0 {
			statusStr = string(content)
		}
	}
	return statusStr
}

func (s *LinuxSecurityHardeningSensor) getSELinuxStatus() string {
	statusStr := "not found"
	hSELinuxConfigFileName := hostPath(seLinuxConfigFileName)
	conFile, err := os.Open(hSELinuxConfigFileName)
	if err == nil {
		defer conFile.Close()
		content, err := readFileOnHostFileSystem(seLinuxConfigFileName)
		if err == nil && len(content) > 0 {
			statusStr = string(content)
		}
	}
	return statusStr
}
