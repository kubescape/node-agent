package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// VerifyEbpf checks if the node-agent ebpf features can run on the current system.
func VerifyEbpf() error {
	if err := checkBTFSupport(); err != nil {
		return err
	}
	// Log a warning if eBPF is not supported (but don't return an error because some distros have backported eBPF support).
	if err := checkEBPFSupport(); err != nil {
		logger.L().Warning("Kernel version is older than 4.4", helpers.Error(err))
	}
	return nil
}

// CheckBTFSupport checks for BTF support.
func checkBTFSupport() error {
	// Check for vmlinux BTF file
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		return nil // vmlinux BTF file found
	}

	btfPaths := []string{
		"/boot/vmlinux-$(uname -r)",
		"/lib/modules/$(uname -r)/vmlinux",
	}

	for _, path := range btfPaths {
		expandedPath, err := exec.Command("sh", "-c", fmt.Sprintf("echo %s", path)).Output()
		if err == nil {
			if _, err := os.Stat(strings.TrimSpace(string(expandedPath))); err == nil {
				return nil // BTF file found
			}
		}
	}

	// Check if BTF is enabled in the kernel
	cmd := exec.Command("sh", "-c", "grep -q CONFIG_DEBUG_INFO_BTF=y /boot/config-$(uname -r)")
	if err := cmd.Run(); err == nil {
		return nil // BTF is enabled in kernel config
	}

	return errors.New("BTF support not detected")
}

// CheckEBPFSupport checks for eBPF support.
func checkEBPFSupport() error {
	// Check kernel version (eBPF is fully supported since Linux 4.4)
	kernelVersion, err := getKernelVersion()
	if err != nil {
		return err
	}
	if !isKernelVersionSupported(kernelVersion) {
		return errors.New("eBPF is not supported: kernel version is too old, version " + kernelVersion)
	}
	return nil
}

func getKernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return "", errors.New("unexpected format in /proc/version")
	}
	return fields[2], nil
}

func isKernelVersionSupported(version string) bool {
	// Simple check: assume version string starts with major.minor
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	major := parts[0]
	minor := parts[1]

	// Convert to integers for comparison
	majorInt := 0
	minorInt := 0
	_, err := fmt.Sscanf(major+"."+minor, "%d.%d", &majorInt, &minorInt)
	if err != nil {
		return false
	}

	// Check if version is at least 4.4
	return majorInt > 4 || (majorInt == 4 && minorInt >= 4)
}
