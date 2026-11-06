package integration

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// podCgroupLayout is how the kubelet of this node names pod cgroups: the
// kubepods cgroup and the cgroup driver. The kubelet creates the pod cgroup
// before the pod sandbox, so a pod cgroup bound at that time covers the first
// exec of every container of the pod.
//
//	systemd:  <root>/kubepods-burstable.slice/kubepods-burstable-pod<uid_>.slice
//	cgroupfs: <root>/burstable/pod<uid>
//
// Guaranteed pods are directly under the root. The root (for example
// /kubepods.slice, or /kubelet.slice/kubelet-kubepods.slice in kind) is read
// from the cgroup path of a running pod container.
type podCgroupLayout struct {
	root    string
	systemd bool
}

// learnPodCgroupLayout reads the layout from the cgroup v2 path of a container
// of pod uid. It returns false when the path has no pod cgroup of that pod.
func learnPodCgroupLayout(cgroupPath string, uid types.UID) (podCgroupLayout, bool) {
	if uid == "" || !path.IsAbs(cgroupPath) || path.Clean(cgroupPath) != cgroupPath {
		return podCgroupLayout{}, false
	}
	parts := strings.Split(cgroupPath, "/")
	for i := 2; i < len(parts); i++ {
		for _, systemd := range []bool{true, false} {
			// QoS levels first: a BestEffort pod cgroup also reads as a
			// Guaranteed one under a root named after the QoS level.
			for _, qos := range []corev1.PodQOSClass{corev1.PodQOSBestEffort, corev1.PodQOSBurstable, corev1.PodQOSGuaranteed} {
				levels := 1
				if qos != corev1.PodQOSGuaranteed {
					levels = 2
				}
				if i-levels < 1 {
					continue
				}
				layout := podCgroupLayout{root: strings.Join(parts[:i+1-levels], "/"), systemd: systemd}
				if layout.path(uid, qos) == strings.Join(parts[:i+1], "/") {
					return layout, true
				}
			}
		}
	}
	return podCgroupLayout{}, false
}

// path returns the pod cgroup path of a pod, or "" when the QoS class is not known.
func (l podCgroupLayout) path(uid types.UID, qos corev1.PodQOSClass) string {
	if l.root == "" || uid == "" || strings.ContainsAny(string(uid), "/ \t\r\n") {
		return ""
	}
	var level string
	switch qos {
	case corev1.PodQOSGuaranteed:
	case corev1.PodQOSBurstable, corev1.PodQOSBestEffort:
		level = strings.ToLower(string(qos))
	default:
		return ""
	}
	if !l.systemd {
		return path.Join(l.root, level, "pod"+string(uid))
	}
	// systemd escapes "-" as "_" in a slice name; "-" separates the levels.
	parent := strings.TrimSuffix(path.Base(l.root), ".slice")
	if parent == path.Base(l.root) {
		return ""
	}
	dir := l.root
	if level != "" {
		parent += "-" + level
		dir = path.Join(dir, parent+".slice")
	}
	return path.Join(dir, parent+"-pod"+strings.ReplaceAll(string(uid), "-", "_")+".slice")
}
