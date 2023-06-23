package validator

import (
	"fmt"
	"node-agent/pkg/config"
	"os"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/facette/natsort"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"golang.org/x/sys/unix"
)

const (
	KubescapeEBPFEngineMinKernelVersionSupport = "5.4"
)

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

func checkKernelVersion(minKernelVersion string) error {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("checkKernelVersion: fail to detect the kernel version")
	}
	kernelVersion := int8ToStr(uname.Sysname[:]) + "," + int8ToStr(uname.Release[:]) + "," + int8ToStr(uname.Version[:])
	logger.L().Debug("kernelVersion", helpers.String("is", kernelVersion))

	// use natsort because 5.15 is greater than 5.4 but not from a string comparison perspective
	if natsort.Compare(int8ToStr(uname.Release[:]), minKernelVersion) {
		return fmt.Errorf("checkKernelVersion: the current kernel version %s is less than the min kernel version support %s", int8ToStr(uname.Release[:]), minKernelVersion)
	}

	return nil
}

// see https://github.com/inspektor-gadget/inspektor-gadget/pull/1809
//
// workaroundMounts ensures that filesystems are mounted correctly.
// Some environments (e.g. minikube) runs with a read-only /sys without bpf
// https://github.com/kubernetes/minikube/blob/99a0c91459f17ad8c83c80fc37a9ded41e34370c/deploy/kicbase/entrypoint#L76-L81
// Docker Desktop with WSL2 also has filesystems unmounted.
func workaroundMounts() error {
	fs := []struct {
		name  string
		path  string
		magic int64
	}{
		{
			"bpf",
			"/sys/fs/bpf",
			unix.BPF_FS_MAGIC,
		},
		{
			"debugfs",
			"/sys/kernel/debug",
			unix.DEBUGFS_MAGIC,
		},
		{
			"tracefs",
			"/sys/kernel/tracing",
			unix.TRACEFS_MAGIC,
		},
	}
	for _, f := range fs {
		var statfs unix.Statfs_t
		err := unix.Statfs(f.path, &statfs)
		if err != nil {
			return fmt.Errorf("statfs %s: %w", f.path, err)
		}
		if statfs.Type == f.magic {
			logger.L().Debug("already mounted", helpers.String("name", f.name), helpers.String("path", f.path))
		} else {
			err := unix.Mount("none", f.path, f.name, 0, "")
			if err != nil {
				return fmt.Errorf("mounting %s: %w", f.path, err)
			}
			logger.L().Debug("mounted", helpers.String("name", f.name), helpers.String("path", f.path))
		}
	}
	return nil
}

func CheckPrerequisites() error {
	// Check kernel version
	logger.L().Debug("checking kernel version")
	if err := checkKernelVersion(KubescapeEBPFEngineMinKernelVersionSupport); err != nil {
		return err
	}
	// Get Node name from environment variable
	logger.L().Debug("checking node name")
	if nodeName := os.Getenv(config.NodeNameEnvVar); nodeName == "" {
		return fmt.Errorf("%s environment variable not set", config.NodeNameEnvVar)
	}
	// Ensure all filesystems are mounted
	logger.L().Debug("checking mounts")
	if err := workaroundMounts(); err != nil {
		return err
	}
	// Raise the rlimit for memlock to the maximum allowed (eBPF needs it)
	logger.L().Debug("raising memlock rlimit")
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	return nil
}
