package sensor

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	ds "github.com/kubescape/node-agent/sensor/datastructures"
	"github.com/kubescape/node-agent/sensor/internal/utils"
)

const (
	etcDirName               = "/etc"
	osReleaseFileSuffix      = "os-release"
	appArmorProfilesFileName = "/sys/kernel/security/apparmor/profiles"
	seLinuxConfigFileName    = "/etc/selinux/semanage.conf"
)

func SenseOsRelease() ([]byte, error) {
	osFileName, err := getOsReleaseFile()
	if err == nil {
		return utils.ReadFileOnHostFileSystem(path.Join(etcDirName, osFileName))
	}
	return []byte{}, fmt.Errorf("failed to find os-release file: %v", err)
}

func getOsReleaseFile() (string, error) {
	hostEtcDir := utils.HostPath(etcDirName)
	etcDir, err := os.Open(hostEtcDir)
	if err != nil {
		return "", fmt.Errorf("failed to open etc dir: %v", err)
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
	return "", err
}

func SenseKernelVersion() ([]byte, error) {
	return utils.ReadFileOnHostFileSystem(path.Join(procDirName, "version"))
}

func getAppArmorStatus() string {
	statusStr := "unloaded"
	hostAppArmorProfilesFileName := utils.HostPath(appArmorProfilesFileName)
	profFile, err := os.Open(hostAppArmorProfilesFileName)
	if err == nil {
		defer profFile.Close()
		statusStr = "stopped"
		content, err := utils.ReadFileOnHostFileSystem(appArmorProfilesFileName)
		if err == nil && len(content) > 0 {
			statusStr = string(content)
		}
	}
	return statusStr
}

func getSELinuxStatus() string {
	statusStr := "not found"
	hostAppArmorProfilesFileName := utils.HostPath(seLinuxConfigFileName)
	conFile, err := os.Open(hostAppArmorProfilesFileName)
	if err == nil {
		defer conFile.Close()
		content, err := utils.ReadFileOnHostFileSystem(appArmorProfilesFileName)
		if err == nil && len(content) > 0 {
			statusStr = string(content)
		}
	}
	return statusStr
}

func SenseLinuxSecurityHardening() (*ds.LinuxSecurityHardeningStatus, error) {
	res := ds.LinuxSecurityHardeningStatus{}

	res.AppArmor = getAppArmorStatus()
	res.SeLinux = getSELinuxStatus()

	return &res, nil
}
