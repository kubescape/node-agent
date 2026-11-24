package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
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

// podSandbox is what the start gate knows of a new pod sandbox: the NRI
// payload, and the pod's QoS class from the API.
type podSandbox struct {
	UID types.UID
	// QoS is the pod's QoS class, "" when not known.
	QoS corev1.PodQOSClass
	// CgroupParent is the payload's Linux.CgroupParent: a cgroupfs path, or
	// a systemd slice name.
	CgroupParent string
	// PausePID is the payload's Pid, the host PID of the pause process.
	PausePID uint32
}

// podCgroupResolver resolves the pod cgroup of a new pod sandbox (design
// §1): from the learned layout, otherwise from the payload's CgroupParent;
// the pause process must be in that cgroup or below it. Anything else is
// unresolved, and the pod is Unknown.
type podCgroupResolver struct {
	layout      podCgroupLayout
	layoutKnown bool
	// readCgroup returns /proc/<pid>/cgroup of a host PID as read in the
	// initial cgroup namespace (readPauseCgroup in production).
	readCgroup func(pid uint32) ([]byte, error)
	// id returns the cgroup ID of a cgroup path (Service.podCgroupID).
	id func(path string) (uint64, error)
}

// newPodCgroupResolver returns the production resolver: the pause process's
// cgroup is read with igbackend's pinned initial-cgroupns reader under a
// pidfd (readPauseCgroup), never in node-agent's own cgroup namespace.
func newPodCgroupResolver(layout podCgroupLayout, known bool, procRoot string, id func(string) (uint64, error)) podCgroupResolver {
	return podCgroupResolver{layout: layout, layoutKnown: known, id: id, readCgroup: func(pid uint32) ([]byte, error) {
		return readPauseCgroup(pid, func() ([]byte, error) { return igbackend.ReadHostProcessCgroup(procRoot, pid) })
	}}
}

// resolve returns the path and the cgroup ID of the pod cgroup.
func (r podCgroupResolver) resolve(pod podSandbox) (string, uint64, error) {
	if r.id == nil || r.readCgroup == nil {
		return "", 0, fmt.Errorf("no cgroup reader")
	}
	pause, err := processCgroup(r.readCgroup, pod.PausePID)
	if err != nil {
		return "", 0, fmt.Errorf("pause process: %w", err)
	}
	var candidates []string
	if r.layoutKnown {
		qos := []corev1.PodQOSClass{pod.QoS}
		if pod.QoS == "" {
			qos = []corev1.PodQOSClass{corev1.PodQOSGuaranteed, corev1.PodQOSBurstable, corev1.PodQOSBestEffort}
		}
		for _, q := range qos {
			if p := r.layout.path(pod.UID, q); p != "" {
				candidates = append(candidates, p)
			}
		}
	}
	if len(candidates) == 0 {
		p, err := cgroupParentPath(pod.CgroupParent, pod.UID)
		if err != nil {
			return "", 0, err
		}
		candidates = append(candidates, p)
	}
	var matched []string
	for _, c := range candidates {
		if pause == c || strings.HasPrefix(pause, c+"/") {
			matched = append(matched, c)
		}
	}
	if len(matched) != 1 {
		return "", 0, fmt.Errorf("pause process cgroup %s is not under the pod cgroup (candidates %v)", pause, candidates)
	}
	id, err := r.id(matched[0])
	if err != nil {
		return "", 0, fmt.Errorf("pod cgroup %s: %w", matched[0], err)
	}
	if id == 0 {
		return "", 0, fmt.Errorf("pod cgroup %s has no ID", matched[0])
	}
	return matched[0], id, nil
}

// processCgroup returns the cgroup v2 path of a process from its
// /proc/<pid>/cgroup, as read. A path outside the reader's cgroup namespace
// ("/..") is refused: it cannot be compared with a host path.
func processCgroup(read func(pid uint32) ([]byte, error), pid uint32) (string, error) {
	if pid == 0 {
		return "", fmt.Errorf("no PID")
	}
	data, err := read(pid)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		p, ok := strings.CutPrefix(scanner.Text(), "0::")
		if !ok {
			continue
		}
		if !path.IsAbs(p) || path.Clean(p) != p || p == "/.." || strings.HasPrefix(p, "/../") {
			return "", fmt.Errorf("cgroup path %q is not a host path", p)
		}
		return p, nil
	}
	return "", fmt.Errorf("process %d has no cgroup v2 path", pid)
}

// cgroupParentPath returns the pod cgroup path that a CgroupParent names:
// a cgroupfs path as is, a systemd slice expanded as systemd does
// (a-b-c.slice is /a.slice/a-b.slice/a-b-c.slice). Its last element must
// be the pod cgroup of uid.
func cgroupParentPath(parent string, uid types.UID) (string, error) {
	if uid == "" || strings.ContainsAny(string(uid), "/ \t\r\n") {
		return "", fmt.Errorf("invalid pod UID %q", uid)
	}
	if strings.HasPrefix(parent, "/") {
		if path.Clean(parent) != parent || path.Base(parent) != "pod"+string(uid) {
			return "", fmt.Errorf("cgroup parent %q is not the cgroup of pod %s", parent, uid)
		}
		return parent, nil
	}
	name, ok := strings.CutSuffix(parent, ".slice")
	if !ok || strings.Contains(name, "/") {
		return "", fmt.Errorf("cgroup parent %q is neither a path nor a slice", parent)
	}
	parts := strings.Split(name, "-")
	if !strings.HasSuffix(name, "-pod"+strings.ReplaceAll(string(uid), "-", "_")) || len(parts) < 2 {
		return "", fmt.Errorf("cgroup parent %q is not the slice of pod %s", parent, uid)
	}
	dir := ""
	for i := range parts {
		if parts[i] == "" {
			return "", fmt.Errorf("cgroup parent %q has an empty slice level", parent)
		}
		dir += "/" + strings.Join(parts[:i+1], "-") + ".slice"
	}
	return dir, nil
}
