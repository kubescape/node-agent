package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/utils"
	"path/filepath"
	"time"

	"github.com/dustin/go-humanize"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/prometheus/procfs"
)

func getExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		return event.Args[0]
	}
	return event.Comm
}

func getContainerFromApplicationProfile(ap *v1beta1.ApplicationProfile, containerName string) (v1beta1.ApplicationProfileContainer, error) {
	for i := range ap.Spec.Containers {
		if ap.Spec.Containers[i].Name == containerName {
			return ap.Spec.Containers[i], nil
		}
	}
	for i := range ap.Spec.InitContainers {
		if ap.Spec.InitContainers[i].Name == containerName {
			return ap.Spec.InitContainers[i], nil
		}
	}
	for i := range ap.Spec.EphemeralContainers {
		if ap.Spec.EphemeralContainers[i].Name == containerName {
			return ap.Spec.EphemeralContainers[i], nil
		}
	}
	return v1beta1.ApplicationProfileContainer{}, fmt.Errorf("container %s not found in application profile", containerName)
}

func getContainerMountPaths(namespace, podName, containerName string, k8sObjCache objectcache.K8sObjectCache) ([]string, error) {
	podSpec := k8sObjCache.GetPodSpec(namespace, podName)
	if podSpec == nil {
		return []string{}, fmt.Errorf("pod spec not available for %s/%s", namespace, podName)
	}

	mountPaths := []string{}
	for _, container := range podSpec.Containers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.InitContainers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	for _, container := range podSpec.EphemeralContainers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	return mountPaths, nil
}

func getPathFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	path, err := proc.Executable()
	if err != nil {
		return "", err
	}

	return path, nil
}

func getCommFromPid(pid uint32) (string, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return "", err
	}

	proc, err := fs.Proc(int(pid))
	if err != nil {
		return "", err
	}

	comm, err := proc.Comm()
	if err != nil {
		return "", err
	}

	return comm, nil
}

func enrichRuleFailure(event igtypes.Event, pid uint32, ruleFailure *GenericRuleFailure) {
	path, err := getPathFromPid(pid)
	hostPath := ""
	if err != nil {
		logger.L().Error("Failed to get path from event", helpers.Error(err))
		path = ""
	} else {
		hostPath = filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", pid, path))
	}

	// Enrich BaseRuntimeAlert
	if ruleFailure.BaseRuntimeAlert.MD5Hash == "" && hostPath != "" {
		md5hash, err := utils.CalculateMD5FileHash(hostPath)
		if err != nil {
			logger.L().Error("Failed to calculate md5 hash for file", helpers.Error(err))
			md5hash = ""
		}
		ruleFailure.BaseRuntimeAlert.MD5Hash = md5hash
	}

	if ruleFailure.BaseRuntimeAlert.SHA1Hash == "" && hostPath != "" {
		sha1hash, err := utils.CalculateSHA1FileHash(hostPath)
		if err != nil {
			logger.L().Error("Failed to calculate sha1 hash for file", helpers.Error(err))
			sha1hash = ""
		}

		ruleFailure.BaseRuntimeAlert.SHA1Hash = sha1hash
	}

	if ruleFailure.BaseRuntimeAlert.SHA256Hash == "" && hostPath != "" {
		sha256hash, err := utils.CalculateSHA256FileHash(hostPath)
		if err != nil {
			logger.L().Error("Failed to calculate sha256 hash for file", helpers.Error(err))
			sha256hash = ""
		}

		ruleFailure.BaseRuntimeAlert.SHA256Hash = sha256hash
	}

	if ruleFailure.BaseRuntimeAlert.Size == nil && hostPath != "" {
		size, err := utils.GetFileSize(hostPath)
		if err != nil {
			logger.L().Error("Failed to get file size", helpers.Error(err))
			sizeStr := ""
			ruleFailure.BaseRuntimeAlert.Size = &sizeStr
		} else {
			size := humanize.Bytes(uint64(size))
			ruleFailure.BaseRuntimeAlert.Size = &size
		}
	}

	if ruleFailure.BaseRuntimeAlert.CommandLine == nil {
		commandLine, err := utils.GetCmdlineByPid(int(pid))
		if err != nil {
			logger.L().Info("Failed to get command line by pid", helpers.Error(err))
			commandLine = nil
		}
		ruleFailure.BaseRuntimeAlert.CommandLine = commandLine
	}

	if ruleFailure.BaseRuntimeAlert.PPID == nil {
		parent, err := utils.GetParentByPid(int(pid))
		if err != nil {
			logger.L().Info("Failed to get ppid by pid", helpers.Error(err))
			ruleFailure.BaseRuntimeAlert.PPID = nil
		} else {
			ppidInt := uint32(parent.PPID)
			ruleFailure.BaseRuntimeAlert.PPID = &ppidInt
		}

		if ruleFailure.BaseRuntimeAlert.PPIDComm == nil {
			if err == nil {
				pcomm := parent.Comm
				ruleFailure.BaseRuntimeAlert.PPIDComm = &pcomm
			} else {
				ruleFailure.BaseRuntimeAlert.PPIDComm = nil
			}
		}
	}

	ruleFailure.BaseRuntimeAlert.Timestamp = time.Unix(int64(event.Timestamp)/1e9, 0)

	// Enrich RuntimeProcessDetails
	if ruleFailure.RuntimeProcessDetails.PID == 0 {
		ruleFailure.RuntimeProcessDetails.PID = pid
	}

	if ruleFailure.RuntimeProcessDetails.Path == "" {
		ruleFailure.RuntimeProcessDetails.Path = path
	}

	if ruleFailure.RuntimeProcessDetails.Comm == "" {
		comm, err := getCommFromPid(pid)
		if err != nil {
			logger.L().Error("Failed to get comm from pid", helpers.Error(err))
			comm = ""
		}
		ruleFailure.RuntimeProcessDetails.Comm = comm
	}

	// Enrich RuntimeAlertK8sDetails
	if ruleFailure.RuntimeAlertK8sDetails.Image == "" {
		ruleFailure.RuntimeAlertK8sDetails.Image = event.GetContainerImageName()
	}

	if ruleFailure.RuntimeAlertK8sDetails.ImageDigest == "" {
		ruleFailure.RuntimeAlertK8sDetails.ImageDigest = event.Runtime.ContainerImageDigest
	}

	if ruleFailure.RuntimeAlertK8sDetails.Namespace == "" {
		ruleFailure.RuntimeAlertK8sDetails.Namespace = event.GetNamespace()
	}

	if ruleFailure.RuntimeAlertK8sDetails.PodName == "" {
		ruleFailure.RuntimeAlertK8sDetails.PodName = event.GetPod()
	}

	if ruleFailure.RuntimeAlertK8sDetails.PodNamespace == "" {
		ruleFailure.RuntimeAlertK8sDetails.PodNamespace = event.GetNamespace()
	}

	if ruleFailure.RuntimeAlertK8sDetails.ContainerName == "" {
		ruleFailure.RuntimeAlertK8sDetails.ContainerName = event.GetContainer()
	}

	if ruleFailure.RuntimeAlertK8sDetails.ContainerID == "" {
		ruleFailure.RuntimeAlertK8sDetails.ContainerID = event.Runtime.ContainerID
	}

	if ruleFailure.RuntimeAlertK8sDetails.HostNetwork == nil {
		ruleFailure.RuntimeAlertK8sDetails.HostNetwork = &event.K8s.HostNetwork
	}
}
