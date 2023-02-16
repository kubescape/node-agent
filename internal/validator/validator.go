package validator

import (
	"fmt"
	"sniffer/pkg/config"
	"syscall"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	FALCO_EBPF_ENGINE_MIN_KERNEL_VERSION_SUPPORT     = "4.14"
	KUBESCAPE_EBPF_ENGINE_MIN_KERNEL_VERSION_SUPPORT = "5.1"
)

var minKernelVersion string

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func checkKernelVersion() error {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("checkKernelVersion: fail to detect the kernel version")
	}
	kernelVersion := int8ToStr(uname.Sysname[:]) + "," + int8ToStr(uname.Release[:]) + "," + int8ToStr(uname.Version[:])
	logger.L().Debug("", helpers.String("kernelVersion: %s", kernelVersion))

	if int8ToStr(uname.Release[:]) < minKernelVersion {
		return fmt.Errorf("checkKernelVersion: the current kernel version %s is less than the min kernel version support %s", int8ToStr(uname.Release[:]), minKernelVersion)
	}

	return nil
}

func checkNodePrerequisites() error {
	if config.GetConfigurationConfigContext().IsFalcoEbpfEngine() {
		minKernelVersion = FALCO_EBPF_ENGINE_MIN_KERNEL_VERSION_SUPPORT
	} else {
		minKernelVersion = KUBESCAPE_EBPF_ENGINE_MIN_KERNEL_VERSION_SUPPORT
	}
	err := checkKernelVersion()
	if err != nil {
		return err
	}
	return nil
}

func CheckPrerequisites() error {
	err := checkNodePrerequisites()
	if err != nil {
		return err
	}
	return nil
}
