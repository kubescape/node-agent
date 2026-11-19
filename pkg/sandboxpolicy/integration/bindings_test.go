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

// A live container that the policies select, or may select, but that kubelet
// has not yet reported Running fails the selected snapshot as binding pending.
func TestSelectedSnapshotLiveUncorrelatedIsBindingPending(t *testing.T) {
	// sidecar is declared in the pod spec; IG discovered it before kubelet
	// reported it Running.
	lateFixture := func() (*corev1.Pod, *corev1.Namespace, []*containercollection.Container) {
		p, ns, containers := bindingFixtures()
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "sidecar"})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: "sidecar", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}})
		late := *containers[0]
		late.Runtime.ContainerID = strings.Repeat("e", 64)
		late.K8s.ContainerName = "sidecar"
		late.K8s.PodLabels = map[string]string{"app": "current"}
		late.CgroupID, late.Mntns, late.Runtime.ContainerPID = 200, 2000, 20000
		return p, ns, append(containers, &late)
	}
	lateKey := "containerd://" + strings.Repeat("e", 64)
	selectCurrent := func(b sandboxpolicy.Binding) bool {
		return b.PodLabels["app"] == "current" && b.NamespaceLabels["team"] == "red"
	}
	cases := []struct {
		name     string
		mutate   func(*corev1.Pod, *corev1.Namespace, []*containercollection.Container) []*containercollection.Container
		selector func(sandboxpolicy.Binding) bool
		pending  int // 0: no pending error
		bindings int // correlated bindings returned either way
	}{
		{name: "selected and correlated is ready", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			return c[:3]
		}, selector: selectCurrent, bindings: 3},
		{name: "selected live not yet running is pending", selector: selectCurrent, pending: 1, bindings: 3},
		{name: "selected live without status entry is pending", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses = p.Status.ContainerStatuses[:1]
			return c
		}, selector: selectCurrent, pending: 1, bindings: 3},
		{name: "every pending container is counted", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			second := *c[3]
			second.Runtime.ContainerID = strings.Repeat("f", 64)
			second.CgroupID = 201
			return append(c, &second)
		}, selector: selectCurrent, pending: 2, bindings: 3},
		{name: "stale IG labels still select until kubelet reports", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Labels = map[string]string{"app": "relabelled"}
			return c
		}, selector: func(b sandboxpolicy.Binding) bool {
			return b.PodLabels["app"] == "current" && b.ContainerName == "sidecar"
		}, pending: 1},
		{name: "unenriched IG metadata fails closed", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[3].K8s.PodUID = ""
			c[3].K8s.PodLabels = nil
			return c
		}, selector: selectCurrent, pending: 1, bindings: 3},
		{name: "unknown IG namespace fails closed", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[3].K8s.PodUID = ""
			c[3].K8s.Namespace = "new-ns"
			return c
		}, selector: selectCurrent, pending: 1, bindings: 3},
		{name: "not selected is unaffected", selector: func(b sandboxpolicy.Binding) bool {
			return selectCurrent(b) && b.ContainerName != "sidecar"
		}, bindings: 3},
		{name: "running but unselected is settled by the API", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses[1].ContainerID = lateKey
			p.Status.ContainerStatuses[1].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
			return c
		}, selector: func(b sandboxpolicy.Binding) bool {
			return b.ContainerName != "sidecar" || b.PodUID == ""
		}, bindings: 3},
		{name: "terminating pod is not pending", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			now := metav1.Now()
			p.DeletionTimestamp = &now
			return c
		}, selector: selectCurrent, bindings: 3},
		{name: "terminal pod phase is not pending", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.Phase = corev1.PodFailed
			return c
		}, selector: selectCurrent, bindings: 3},
		{name: "exited container is not pending", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses[1].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: lateKey}}
			return c
		}, selector: selectCurrent, bindings: 3},
		{name: "previous restart is not pending", mutate: func(p *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			p.Status.ContainerStatuses[1].LastTerminationState = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: lateKey}}
			return c
		}, selector: selectCurrent, bindings: 3},
		{name: "deleted pod is not pending", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[3].K8s.PodUID = "deleted-pod"
			return c
		}, selector: selectCurrent, bindings: 3},
		{name: "non-Kubernetes container is not pending", mutate: func(_ *corev1.Pod, _ *corev1.Namespace, c []*containercollection.Container) []*containercollection.Container {
			c[3].K8s = containercollection.K8sMetadata{}
			return c
		}, selector: selectCurrent, bindings: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ns, c := lateFixture()
			if tc.mutate != nil {
				c = tc.mutate(p, ns, c)
			}
			got, err := SnapshotSelectedBindingsFromContainers(context.Background(), fake.NewSimpleClientset(p, ns), c, "node", tc.selector)
			if tc.pending == 0 {
				if err != nil || len(got) != tc.bindings {
					t.Fatalf("want %d bindings, got %d: %v", tc.bindings, len(got), err)
				}
				return
			}
			// Pending is non-fatal: the correlated set comes back with it.
			var pending *sandboxpolicy.BindingPendingError
			if !errors.As(err, &pending) || got == nil || len(got) != tc.bindings {
				t.Fatalf("want binding pending with %d bindings, got %+v / %v", tc.bindings, got, err)
			}
			if pending.Containers != tc.pending {
				t.Fatalf("want %d pending, got %d", tc.pending, pending.Containers)
			}
		})
	}
}

func TestSelectedFenceCensusMissingObserverContainerIsNotGlobalBarrier(t *testing.T) {
	pod, ns, containers := bindingFixtures()
	agent := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: "ns", UID: "agent-pod"},
		Spec:       corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "agent"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "agent", ContainerID: "containerd://" + strings.Repeat("f", 64),
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
	client := fake.NewSimpleClientset(pod, ns, agent)
	// No namespace or self-agent exemption: exact API selection decides which
	// missing container is required, while correlated siblings remain present.
	selectApp := func(b sandboxpolicy.Binding) bool { return b.PodUID == pod.UID && b.ContainerName == "app" }
	census, err := SnapshotSelectedFenceBindingsFromContainers(t.Context(), client, containers, "node", selectApp)
	if err != nil || len(census.Members) != 3 || len(census.Pending) != 0 {
		t.Fatalf("unselected observer exclusion blocked correlated workload: %+v %v", census, err)
	}
	for i, b := range census.Members {
		if b.ContainerID != containers[i].Runtime.ContainerID || b.PodUID != pod.UID || b.PodLabels["app"] != "current" {
			t.Fatalf("lost authoritative sibling identity: %+v", b)
		}
	}
	if census, err := SnapshotSelectedFenceBindingsFromContainers(t.Context(), client, containers, "node", func(sandboxpolicy.Binding) bool { return true }); err == nil || len(census.Members) != 0 {
		t.Fatalf("explicitly selected ignored agent silently exempted: %+v %v", census, err)
	}
	// Deleting/offlining policies still yields exact existing identities, which
	// let the manager perform authorized withdrawal rather than retain forever.
	census, err = SnapshotSelectedFenceBindingsFromContainers(t.Context(), client, containers, "node", func(sandboxpolicy.Binding) bool { return false })
	if err != nil || len(census.Members) != 3 {
		t.Fatalf("no-policy census lost withdrawal identities: %+v %v", census, err)
	}
	if _, err := SnapshotFenceBindingsFromContainers(t.Context(), client, containers, "node"); err == nil {
		t.Fatal("strict-all census behavior changed")
	}
}

func TestSelectedFenceCensusUncorrelatedUsesSelectionAndSettledEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		selectLate bool
		settled    bool
	}{{"selected pending", true, false}, {"unselected not pending", false, false}, {"exited not pending", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			pod, ns, containers := bindingFixtures()
			pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "late"})
			late := *containers[0]
			late.Runtime.ContainerID = strings.Repeat("e", 64)
			late.K8s.ContainerName = "late"
			late.CgroupID = 200
			if tc.settled {
				pod.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{ContainerID: "containerd://" + late.Runtime.ContainerID}
			}
			selected := func(b sandboxpolicy.Binding) bool {
				return b.ContainerName == "app" || tc.selectLate && b.ContainerName == "late"
			}
			census, err := SnapshotSelectedFenceBindingsFromContainers(t.Context(), fake.NewSimpleClientset(pod, ns), append(containers, &late), "node", selected)
			wantPending := tc.selectLate && !tc.settled
			var pending *sandboxpolicy.BindingPendingError
			if errors.As(err, &pending) != wantPending || (!wantPending && err != nil) || len(census.Members) != 3 {
				t.Fatalf("wrong census/pending outcome: %+v %v", census, err)
			}
			if wantPending {
				if pending.Containers != 1 || len(census.Pending) != 1 || census.Pending[0].ContainerID != late.Runtime.ContainerID || census.Pending[0].PodLabels != nil {
					t.Fatalf("pending hint became missing or authoritative: %+v", census.Pending)
				}
			} else if len(census.Pending) != 0 {
				t.Fatalf("irrelevant hint blocks readiness: %+v", census.Pending)
			}
		})
	}
}

func TestSelectedFenceCensusSelectedContradictionFailsClosed(t *testing.T) {
	pod, ns, containers := bindingFixtures()
	containers[0].K8s.PodUID = "wrong"
	census, err := SnapshotSelectedFenceBindingsFromContainers(t.Context(), fake.NewSimpleClientset(pod, ns), containers, "node", func(b sandboxpolicy.Binding) bool { return b.ContainerName == "app" })
	if err == nil || len(census.Members) != 0 || len(census.Pending) != 0 {
		t.Fatalf("selected contradiction accepted: %+v %v", census, err)
	}
	if _, err := SnapshotSelectedFenceBindingsFromContainers(t.Context(), fake.NewSimpleClientset(pod, ns), containers, "node", nil); err == nil {
		t.Fatal("missing authoritative selector accepted")
	}
	if _, err := SnapshotSelectedFenceBindings(t.Context(), fake.NewSimpleClientset(pod, ns), nil, "node", func(sandboxpolicy.Binding) bool { return false }); err == nil {
		t.Fatal("missing discovery collection accepted")
	}
}
