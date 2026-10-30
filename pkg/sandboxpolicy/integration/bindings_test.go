package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgettypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func bindingFixtures() (*corev1.Pod, *corev1.Namespace, []*containercollection.Container) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid", Labels: map[string]string{"app": "current"}}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app"}}, InitContainers: []corev1.Container{{Name: "init"}}, EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}}}}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", Labels: map[string]string{"team": "red"}}}
	var containers []*containercollection.Container
	for i, name := range []string{"app", "init", "debug"} {
		id := strings.Repeat(string(rune('a'+i)), 64)
		status := corev1.ContainerStatus{Name: name, ContainerID: "containerd://" + id, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
		switch i {
		case 0:
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{status}
		case 1:
			pod.Status.InitContainerStatuses = []corev1.ContainerStatus{status}
		case 2:
			pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{status}
		}
		c := &containercollection.Container{CgroupID: uint64(100 + i), CgroupPath: "/sys/fs/cgroup/kubepods/" + id, CgroupV2: "/kubepods/" + id, Mntns: uint64(1000 + i)}
		c.Runtime.RuntimeName = gadgettypes.RuntimeNameContainerd
		c.Runtime.ContainerID = id
		c.Runtime.ContainerPID = uint32(10000 + i)
		c.K8s.Namespace = "ns"
		c.K8s.PodName = "pod"
		c.K8s.PodUID = "pod-uid"
		c.K8s.ContainerName = name
		c.K8s.PodLabels = map[string]string{"app": "stale"}
		containers = append(containers, c)
	}
	return pod, namespace, containers
}
func TestSnapshotBindingsCorrelatesExactRunningIdentities(t *testing.T) {
	pod, namespace, containers := bindingFixtures()
	client := fake.NewSimpleClientset(pod, namespace)
	bindings, err := SnapshotBindingsFromContainers(context.Background(), client, containers, "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 3 {
		t.Fatalf("want three container kinds, got %d", len(bindings))
	}
	for i, b := range bindings {
		if b.Kind != []string{"regular", "init", "ephemeral"}[i] || b.PodUID != "pod-uid" || b.Runtime != "containerd" || b.ContainerID != containers[i].Runtime.ContainerID || b.CgroupID != containers[i].CgroupID || b.CgroupPath != containers[i].CgroupV2 || b.PID != containers[i].Runtime.ContainerPID || b.MountNamespace != containers[i].Mntns || b.PodLabels["app"] != "current" || b.NamespaceLabels["team"] != "red" {
			t.Fatalf("incorrect binding: %+v", b)
		}
	}
	bindings[0].PodLabels["app"] = "mutated"
	if bindings[1].PodLabels["app"] != "current" || pod.Labels["app"] != "current" {
		t.Fatal("snapshot aliases metadata")
	}
	action := client.Actions()[0].(ktesting.ListAction)
	if action.GetListRestrictions().Fields.String() != "spec.nodeName=node" {
		t.Fatal("pod list not node-scoped")
	}
}
func TestSnapshotRejectsDiscoveryGapsWithoutPartialBindings(t *testing.T) {
	cases := map[string]func(*corev1.Pod, *corev1.Namespace, []*containercollection.Container) []*containercollection.Container{
		"missing runtime": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			return c[:2]
		},
		"zero cgroup": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].CgroupID = 0
			return c
		},
		"root cgroup": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].CgroupV2 = "/"
			return c
		},
		"missing PID": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].Runtime.ContainerPID = 0
			return c
		},
		"missing mount": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].Mntns = 0
			return c
		},
		"stale pod UID": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].K8s.PodUID = "old"
			return c
		},
		"partial K8s": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].K8s.Namespace = ""
			return c
		},
		"short container ID": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].Runtime.ContainerID = c[1].Runtime.ContainerID[:12]
			return c
		},
		"status empty ID": func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses[0].ContainerID = ""
			return c
		},
		"unknown runtime": func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses[0].ContainerID = "mystery://id"
			return c
		},
		"duplicate runtime": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			return append(c, c[0])
		},
		"shared cgroup": func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[1].CgroupID = c[0].CgroupID
			return c
		},
		"undeclared container": func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Spec.Containers = nil
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, ns, c := bindingFixtures()
			c = mutate(p, ns, c)
			bindings, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), c, "node")
			if err == nil || bindings != nil {
				t.Fatalf("accepted partial snapshot: %+v / %v", bindings, err)
			}
		})
	}
}
func TestSnapshotSkipsNonKubernetesButNotUncorrelatedKubernetes(t *testing.T) {
	pod, ns, c := bindingFixtures()
	host := &containercollection.Container{}
	host.Runtime.ContainerID = "host"
	c = append(c, host)
	if _, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(pod, ns), c, "node"); err != nil {
		t.Fatal(err)
	}
	host.K8s.PodName = "unmatched"
	if _, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(pod, ns), c, "node"); err == nil {
		t.Fatal("unmatched live Kubernetes discovery silently omitted")
	}
}
func TestSnapshotAPIFailuresAndNodeIsolation(t *testing.T) {
	p, ns, _ := bindingFixtures()
	p.Spec.NodeName = "other"
	bindings, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), nil, "node")
	if err != nil || len(bindings) != 0 {
		t.Fatalf("cross-node pods included: %v", err)
	}
	for _, resource := range []string{"pods", "namespaces"} {
		p, ns, c := bindingFixtures()
		client := fake.NewSimpleClientset(p, ns)
		client.PrependReactor("list", resource, func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("disconnected") })
		if got, err := SnapshotBindingsFromContainers(context.Background(), client, c, "node"); err == nil || got != nil {
			t.Fatal("API failure produced withdrawal snapshot")
		}
	}
	p, _, c := bindingFixtures()
	if _, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p), c, "node"); err == nil {
		t.Fatal("missing namespace labels accepted")
	}
	if _, err := SnapshotBindings(context.Background(), fake.NewSimpleClientset(), nil, "node"); err == nil {
		t.Fatal("nil collection accepted")
	}
}
func TestSnapshotUsesCollectionCurrentEntries(t *testing.T) {
	collection := &containercollection.ContainerCollection{}
	got, err := SnapshotBindings(context.Background(), fake.NewSimpleClientset(), collection, "node")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty snapshot: %v", err)
	}
}

func TestSelectedSnapshotDoesNotRequireUnselectedAgentDiscovery(t *testing.T) {
	p, ns, containers := bindingFixtures()
	agent := p.DeepCopy()
	agent.Name = "node-agent-own"
	agent.UID = "agent-uid"
	agent.Labels = map[string]string{"app": "node-agent"}
	agent.Spec.InitContainers = nil
	agent.Spec.EphemeralContainers = nil
	agent.Status.InitContainerStatuses = nil
	agent.Status.EphemeralContainerStatuses = nil
	agent.Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("d", 64)
	client := fake.NewSimpleClientset(p, ns, agent)
	selectWorkload := func(b sandboxpolicy.Binding) bool { return b.PodLabels["app"] == "current" }
	got, err := SnapshotSelectedBindingsFromContainers(context.Background(), client, containers, "node", selectWorkload)
	if err != nil || len(got) != 3 {
		t.Fatalf("unselected missing agent blocked workload: %+v %v", got, err)
	}
	selectAgent := func(b sandboxpolicy.Binding) bool { return b.PodName == "node-agent-own" }
	if got, err := SnapshotSelectedBindingsFromContainers(context.Background(), client, containers, "node", selectAgent); err == nil || got != nil {
		t.Fatal("explicitly selected ignored agent silently exempted")
	}
	if _, err := SnapshotBindingsFromContainers(context.Background(), client, containers, "node"); err == nil {
		t.Fatal("strict-all API unexpectedly weakened")
	}
}

func TestSelectedSnapshotIgnoresUnmatchedDiscoveryButRejectsSelectedMismatch(t *testing.T) {
	p, ns, containers := bindingFixtures()
	client := fake.NewSimpleClientset(p, ns)
	stale := *containers[0]
	stale.Runtime.ContainerID = "old-runtime-id"
	stale.K8s.PodUID = "old-pod"
	containers = append(containers, &stale, nil)
	selectAll := func(sandboxpolicy.Binding) bool { return true }
	if got, err := SnapshotSelectedBindingsFromContainers(context.Background(), client, containers, "node", selectAll); err != nil || len(got) != 3 {
		t.Fatalf("unmatched discovery blocked selected workloads: %v", err)
	}
	containers[0].K8s.PodUID = "different-pod"
	if got, err := SnapshotSelectedBindingsFromContainers(context.Background(), client, containers, "node", selectAll); err == nil || got != nil {
		t.Fatal("selected runtime identity mismatch silently ignored")
	}
}

func TestSelectedSnapshotSelectsBeforeRequiringRuntimeIdentity(t *testing.T) {
	p, ns, containers := bindingFixtures()
	p.Status.InitContainerStatuses[0].ContainerID = ""
	selectRegular := func(b sandboxpolicy.Binding) bool {
		return b.Kind == "regular" && b.Namespace == "ns" && b.ContainerName == "app" && b.NamespaceLabels["team"] == "red"
	}
	got, err := SnapshotSelectedBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), containers[:1], "node", selectRegular)
	if err != nil || len(got) != 1 {
		t.Fatalf("unselected runtime metadata was required: %v", err)
	}
	if _, err := SnapshotSelectedBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), containers, "node", nil); err == nil {
		t.Fatal("nil selection predicate accepted")
	}
	if _, err := SnapshotSelectedBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p), containers, "node", selectRegular); err == nil {
		t.Fatal("unknown namespace labels inferred as empty")
	}
	if _, err := SnapshotSelectedBindings(context.Background(), fake.NewSimpleClientset(), nil, "node", selectRegular); err == nil {
		t.Fatal("nil discovery collection accepted")
	}
	collection := &containercollection.ContainerCollection{}
	got, err = SnapshotSelectedBindings(context.Background(), fake.NewSimpleClientset(p, ns), collection, "node", func(sandboxpolicy.Binding) bool { return false })
	if err != nil || len(got) != 0 {
		t.Fatalf("no selected policies requires no binding: %v", err)
	}
}

func TestSnapshotRejectsInvalidMembershipDespiteMountedPath(t *testing.T) {
	for _, membership := range []string{"", "relative", "/", "/kubepods/../other", "/kubepods//target"} {
		t.Run(membership, func(t *testing.T) {
			p, ns, containers := bindingFixtures()
			containers[0].CgroupV2 = membership
			got, err := SnapshotBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), containers, "node")
			if err == nil || got != nil {
				t.Fatalf("invalid membership accepted: %+v %v", got, err)
			}
		})
	}
}
