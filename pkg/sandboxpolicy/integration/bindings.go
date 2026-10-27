package integration

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgettypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

// SnapshotBindings joins runtime identities to authoritative Kubernetes metadata.
// The caller must subscribe before snapshotting and reconcile subsequent churn;
// ContainerRange is not an atomic barrier across independent runtime/API watches.
// The backend must still verify live PID/cgroup ownership immediately before bind.
func SnapshotBindings(ctx context.Context, client kubernetes.Interface, collection *containercollection.ContainerCollection, nodeName string) ([]sandboxpolicy.Binding, error) {
	if collection == nil {
		return nil, fmt.Errorf("container collection is unavailable")
	}
	var containers []*containercollection.Container
	collection.ContainerRange(func(container *containercollection.Container) { containers = append(containers, container) })
	return SnapshotBindingsFromContainers(ctx, client, containers, nodeName)
}

// SnapshotBindingsFromContainers accepts the current (not cached/deleted) runtime
// collection. Any incomplete or contradictory live Kubernetes identity rejects
// the entire snapshot, so the caller can retain last-good rather than interpret
// discovery lag as authorization to withdraw enforcement.
func SnapshotBindingsFromContainers(ctx context.Context, client kubernetes.Interface, containers []*containercollection.Container, nodeName string) ([]sandboxpolicy.Binding, error) {
	return snapshotBindings(ctx, client, containers, nodeName, nil)
}

// SnapshotSelectedBindings requires runtime identities only for authoritatively
// selected Kubernetes workloads. It does not inherit observer namespace/agent
// exemptions: an explicitly selected but observer-ignored container still fails
// if discovery cannot provide its exact identity.
func SnapshotSelectedBindings(ctx context.Context, client kubernetes.Interface, collection *containercollection.ContainerCollection, nodeName string, selector func(sandboxpolicy.Binding) bool) ([]sandboxpolicy.Binding, error) {
	if collection == nil {
		return nil, fmt.Errorf("container collection is unavailable")
	}
	var containers []*containercollection.Container
	collection.ContainerRange(func(container *containercollection.Container) { containers = append(containers, container) })
	return SnapshotSelectedBindingsFromContainers(ctx, client, containers, nodeName, selector)
}

// SnapshotSelectedBindingsFromContainers is the selected-only snapshot variant
// for explicit runtime collections. Unmatched entries authorize no binding and
// may be ignored. Missing or contradictory selected identities reject the whole
// snapshot, never silently reducing protection.
func SnapshotSelectedBindingsFromContainers(ctx context.Context, client kubernetes.Interface, containers []*containercollection.Container, nodeName string, selector func(sandboxpolicy.Binding) bool) ([]sandboxpolicy.Binding, error) {
	if selector == nil {
		return nil, fmt.Errorf("selected snapshot requires a policy selector")
	}
	return snapshotBindings(ctx, client, containers, nodeName, selector)
}

func snapshotBindings(ctx context.Context, client kubernetes.Interface, containers []*containercollection.Container, nodeName string, selector func(sandboxpolicy.Binding) bool) ([]sandboxpolicy.Binding, error) {

	if client == nil || nodeName == "" {
		return nil, fmt.Errorf("Kubernetes client and node name are required")
	}
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String()})
	if err != nil {
		return nil, fmt.Errorf("list node pods: %w", err)
	}
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	namespaceLabels := make(map[string]map[string]string, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		namespaceLabels[ns.Name] = copyLabels(ns.Labels)
	}
	expected := make(map[string]sandboxpolicy.Binding)
	for _, pod := range pods.Items {
		// Also filter locally: fake clients and unusual proxies may not honor fields.
		if pod.Spec.NodeName != nodeName {
			continue
		}
		for _, group := range []struct {
			kind     string
			statuses []corev1.ContainerStatus
		}{{"regular", pod.Status.ContainerStatuses}, {"init", pod.Status.InitContainerStatuses}, {"ephemeral", pod.Status.EphemeralContainerStatuses}} {
			for _, status := range group.statuses {
				if status.State.Running == nil {
					continue
				}

				// Select from API metadata before requiring runtime IDs. Namespace labels
				// must be known even for selection; absence is never treated as empty.
				labels, ok := namespaceLabels[pod.Namespace]
				if !ok {
					return nil, fmt.Errorf("namespace %s missing from authoritative snapshot", pod.Namespace)
				}
				metadata := sandboxpolicy.Binding{PodUID: pod.UID, Namespace: pod.Namespace, PodName: pod.Name, ContainerName: status.Name, Kind: group.kind, PodLabels: copyLabels(pod.Labels), NamespaceLabels: copyLabels(labels)}
				if selector != nil && !selector(metadata) {
					continue
				}
				if pod.UID == "" || pod.Name == "" || pod.Namespace == "" || status.Name == "" || !containerDeclared(pod, group.kind, status.Name) {
					return nil, fmt.Errorf("running container in %s/%s has incomplete pod/spec identity", pod.Namespace, pod.Name)
				}
				runtime, id, ok := strings.Cut(status.ContainerID, "://")
				if !ok || gadgettypes.String2RuntimeName(runtime) == gadgettypes.RuntimeNameUnknown || id == "" || strings.ContainsAny(id, "/ \t\r\n") {
					return nil, fmt.Errorf("running container %s/%s/%s has invalid full runtime ID", pod.Namespace, pod.Name, status.Name)
				}

				key := runtime + "://" + id
				if _, duplicate := expected[key]; duplicate {
					return nil, fmt.Errorf("duplicate running runtime identity %s", key)
				}
				metadata.Runtime = runtime
				metadata.ContainerID = id
				expected[key] = metadata
			}
		}
	}
	result := make([]sandboxpolicy.Binding, 0, len(expected))
	seen := make(map[string]bool)
	cgroups := make(map[uint64]string)
	for _, container := range containers {
		if container == nil {
			if selector != nil {
				continue
			}
			return nil, fmt.Errorf("nil live container in runtime snapshot")
		}
		key := string(container.Runtime.RuntimeName) + "://" + container.Runtime.ContainerID
		binding, matched := expected[key]
		if !matched && selector != nil {
			continue
		}
		hasK8s := container.K8s.Namespace != "" || container.K8s.PodName != "" || container.K8s.PodUID != "" || container.K8s.ContainerName != ""
		if !matched && !hasK8s {
			continue
		} // host/ECS/non-Kubernetes discovery is out of scope
		if !matched {
			return nil, fmt.Errorf("live Kubernetes container %s is not correlated with a running node pod", key)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate runtime collection identity %s", key)
		}
		seen[key] = true
		if container.K8s.Namespace != binding.Namespace || container.K8s.PodName != binding.PodName || container.K8s.PodUID != string(binding.PodUID) || container.K8s.ContainerName != binding.ContainerName {
			return nil, fmt.Errorf("runtime/Kubernetes metadata mismatch for %s", key)
		}
		if container.CgroupID == 0 || container.Runtime.ContainerPID == 0 || container.Mntns == 0 || container.CgroupPath == "" || !path.IsAbs(container.CgroupPath) || path.Clean(container.CgroupPath) != container.CgroupPath || container.CgroupPath == "/" {
			return nil, fmt.Errorf("live Kubernetes container %s lacks a strict cgroup/PID/mount identity", key)
		}
		if previous, duplicate := cgroups[container.CgroupID]; duplicate {
			return nil, fmt.Errorf("cgroup ID shared by %s and %s", previous, key)
		}
		cgroups[container.CgroupID] = key
		binding.CgroupID = container.CgroupID
		binding.CgroupPath = container.CgroupPath
		binding.PID = container.Runtime.ContainerPID
		binding.MountNamespace = container.Mntns
		result = append(result, binding)
	}
	for key := range expected {
		if !seen[key] {
			return nil, fmt.Errorf("running Kubernetes container %s missing from runtime discovery", key)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Runtime != result[j].Runtime {
			return result[i].Runtime < result[j].Runtime
		}
		return result[i].ContainerID < result[j].ContainerID
	})
	return result, nil
}

func containerDeclared(pod corev1.Pod, kind, name string) bool {
	switch kind {
	case "regular":
		for _, c := range pod.Spec.Containers {
			if c.Name == name {
				return true
			}
		}
	case "init":
		for _, c := range pod.Spec.InitContainers {
			if c.Name == name {
				return true
			}
		}
	case "ephemeral":
		for _, c := range pod.Spec.EphemeralContainers {
			if c.Name == name {
				return true
			}
		}
	}
	return false
}
func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
