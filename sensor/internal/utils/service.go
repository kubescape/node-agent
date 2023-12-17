package utils

import (
	"context"
	"errors"
	"os"
	"path"

	systemd_debus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// This file contains utilities for the getting information about services

const (
	// https://wiki.archlinux.org/title/Systemd
	systemdPkgDir   = "/usr/lib/systemd/system/" // units provided by installed packages
	systemdAdminDir = "/etc/systemd/system/"     // units installed by the system administrator

	// default service paths
	kubeletSystemdServiceConfigDir = systemdAdminDir + "kubelet.service.d"
)

var (
	ErrServicePathNotFound = errors.New("cannot locate service file path")
)

func newSystemDbusConnection() (*dbus.Conn, error) {
	systemBusPath := "unix:path=" + HostPath("/run/dbus/system_bus_socket")
	d, err := dbus.Dial(systemBusPath)
	if err != nil {
		return d, err
	}
	err = d.Auth(nil)
	if err != nil {
		return d, err
	}
	err = d.Hello()
	return d, err
}

// GetKubeletServiceFiles all the service files associated with the kubelet service.
func GetKubeletServiceFiles(kubeletPid int) ([]string, error) {

	// First try to get the service files from systemd daemon
	configDir, err := GetServiceFilesByPIDSystemd(kubeletPid)
	if err != nil {
		logger.L().Debug("failed to get service files by PID from systemd", helpers.Error(err))
	}

	// Fallback to the default location
	// if can't find the service files path dynamically
	if configDir == "" {
		configDir = kubeletSystemdServiceConfigDir
	}

	files, err := os.ReadDir(HostPath(configDir))
	if err != nil {
		return nil, err
	}

	ret := []string{}
	for _, f := range files {
		ret = append(ret, path.Join(configDir, f.Name()))
	}

	return ret, nil
}

// GetServiceFilesByPIDSystemd returns the serivce config directory for a given process id.
func GetServiceFilesByPIDSystemd(pid int) (string, error) {
	conn, err := systemd_debus.NewConnection(newSystemDbusConnection)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	unitName, err := conn.GetUnitNameByPID(context.Background(), uint32(pid))
	if err != nil {
		return "", err
	}

	// Get the service file path
	// p, err := conn.GetUnitPropertyContext(context.Background(), unitName, "FragmentPath")
	// if err != nil {
	// 	return "", nil, err
	// }
	// servicePath := p.Value.String()
	// servicePath = servicePath[1 : len(servicePath)-1] // remove quotes

	// Find the service override files path (if any)
	unitDirName := unitName + ".d"
	configDir := getExistsPath(HostFileSystemDefaultLocation,
		path.Join(systemdPkgDir, unitDirName),
		path.Join(systemdAdminDir, unitDirName),
	)

	return configDir, nil
}

// getExistsPath return the first exists path from a list of `paths`, prefixing it with `rootDir`.
func getExistsPath(rootDir string, paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(path.Join(rootDir, p)); err == nil {
			return p
		}
	}
	return ""
}
