package integration

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// restartPinDir is the directory of the pinned enforcement sets on the host bpffs.
const restartPinDir = "kubescape-sandbox"

// RestartPinRoot returns the directory for pinned enforcement on the host
// bpffs, or "" when node-agent sees no host bpffs. Only the host root is used:
// the container's own /sys/fs/bpf can be a bpffs that node-agent mounted
// itself (validator workaroundMounts), and that one ends with the container.
func RestartPinRoot() string {
	dir := filepath.Join(host.HostRoot, "sys/fs/bpf")
	if !enforcement.IsBPFFS(dir) {
		return ""
	}
	return filepath.Join(dir, restartPinDir)
}

// RemoveRestartPins removes every pinned enforcement set. Call it when the
// sandbox policy feature is off, so a previous run's sets do not stay.
func RemoveRestartPins() error {
	root := RestartPinRoot()
	if root == "" {
		return nil
	}
	return igbackend.RemoveRestartPins(root)
}

type restartSurvivor interface {
	RestartSurvival(root string) error
}

// enableRestartSurvival turns on restart survival for the node backends that
// run (nil: the section is off) and removes the pinned sets of the sections
// that are off.
func enableRestartSurvival(backends map[string]sandboxpolicy.Backend, report func(error)) {
	root := RestartPinRoot()
	if root == "" {
		logger.L().Warning("sandbox restart survival off: no host bpffs", helpers.String("path", filepath.Join(host.HostRoot, "sys/fs/bpf")))
		return
	}
	for section, backend := range backends {
		if backend == nil {
			if err := igbackend.RemoveRestartPins(root, section); err != nil {
				report(fmt.Errorf("removing %s restart pins: %w", section, err))
			}
			continue
		}
		survivor, ok := backend.(restartSurvivor)
		if !ok {
			continue
		}
		if err := survivor.RestartSurvival(root); err != nil {
			report(fmt.Errorf("%s restart survival: %w", section, err))
			continue
		}
		logger.L().Info("sandbox restart survival on", helpers.String("section", section), helpers.String("root", root))
	}
}

// uninstalling reports whether node-agent stops because its DaemonSet is gone
// or being deleted (helm uninstall, kubectl delete): then no next node-agent
// takes over its pinned sets, and they must not keep enforcing with no owner
// until the next reboot. A rolling update, an eviction or a crash keeps the
// DaemonSet, so the pins stay. Any read error is "not uninstalling": keeping
// the pins fails closed.
func uninstalling(ctx context.Context, client kubernetes.Interface, namespace, pod string) (bool, error) {
	if client == nil || namespace == "" || pod == "" {
		return false, fmt.Errorf("no pod identity to check the DaemonSet")
	}
	p, err := client.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	for _, owner := range p.OwnerReferences {
		if owner.Kind != "DaemonSet" {
			continue
		}
		ds, err := client.AppsV1().DaemonSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return ds.DeletionTimestamp != nil || ds.UID != owner.UID, nil
	}
	return false, nil
}

// removePinsOnUninstall removes every pinned enforcement set when node-agent
// stops because its DaemonSet is deleted (see uninstalling). Call it after
// the backend closed.
func removePinsOnUninstall(ctx context.Context, client kubernetes.Interface, namespace, pod string) error {
	gone, err := uninstalling(ctx, client, namespace, pod)
	if err != nil || !gone {
		return err
	}
	logger.L().Info("sandbox DaemonSet deleted: removing the pinned enforcement sets")
	return RemoveRestartPins()
}
