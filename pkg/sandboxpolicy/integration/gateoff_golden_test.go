package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// goldenBackend records every backend call of the gate-off scenario. It has
// the pod gate's methods too (so a gate-aware code path could reach them),
// and only uses names that exist at HEAD 98c0a432, so the same file runs
// there to produce the golden log.
type goldenBackend struct {
	log     []string
	bindErr error
}

func (b *goldenBackend) add(format string, args ...any) {
	b.log = append(b.log, fmt.Sprintf(format, args...))
}

func goldenPlan(plan sandboxpolicy.Plan) string {
	var parts []string
	for _, p := range plan.Policies {
		parts = append(parts, fmt.Sprintf("%s:%s:priv=%v", p.Identity.UID, p.Mode, p.Privilege != nil))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func (b *goldenBackend) Replace(_ context.Context, binding sandboxpolicy.Binding, p sandboxpolicy.Plan) (sandboxpolicy.ReplaceResult, error) {
	b.add("Replace %s %s", binding.ContainerID, goldenPlan(p))
	return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: p.Revision}, nil
}
func (b *goldenBackend) Withdraw(_ context.Context, binding sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	b.add("Withdraw %s", binding.ContainerID)
	return sandboxpolicy.WithdrawResult{Committed: true}, nil
}
func (b *goldenBackend) Close(context.Context) error  { b.add("Close"); return nil }
func (b *goldenBackend) Settle(context.Context) error { b.add("Settle"); return nil }
func (b *goldenBackend) BindPods(_ context.Context, pods []sandboxpolicy.PodBinding) error {
	var parts []string
	for _, p := range pods {
		parts = append(parts, fmt.Sprintf("%s/%s/%s cgroup=%d path=%s plan=%s started=%v", p.PodUID, p.Namespace, p.PodName, p.CgroupID, p.CgroupPath, goldenPlan(p.Plan), p.ContainersStarted))
	}
	b.add("BindPods [%s]", strings.Join(parts, "; "))
	return b.bindErr
}
func (b *goldenBackend) MarkPod(context.Context, sandboxpolicy.PodBinding, sandboxpolicy.Seq) []sandboxpolicy.PodSectionResult {
	b.add("MarkPod")
	return nil
}
func (b *goldenBackend) EnsurePodBound(context.Context, types.UID, sandboxpolicy.Plan) []sandboxpolicy.PodSectionResult {
	b.add("EnsurePodBound")
	return nil
}
func (b *goldenBackend) ConfirmPod(types.UID, uint64, sandboxpolicy.Plan) []sandboxpolicy.PodSectionConfirmation {
	b.add("ConfirmPod")
	return nil
}
func (b *goldenBackend) ReleasePod(context.Context, types.UID, uint64) error {
	b.add("ReleasePod")
	return nil
}
func (b *goldenBackend) UnmarkPod(context.Context, types.UID, uint64, sandboxpolicy.Seq) error {
	b.add("UnmarkPod")
	return nil
}
func (b *goldenBackend) BindPodsAt(context.Context, []sandboxpolicy.PodBinding, sandboxpolicy.Seq) error {
	b.add("BindPodsAt")
	return nil
}
func (b *goldenBackend) SetStartGate(bool)               { b.add("SetStartGate") }
func (b *goldenBackend) SetCgroupGone(func(uint64) bool) { b.add("SetCgroupGone") }

// gateOffScenario runs main's pod binding and refresh steps on a service
// with one scheduled Strict privilege pod and one container binding, and
// returns the backend's call log.
func gateOffScenario(t *testing.T) []string {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "priv", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"*"}, "privilege": map[string]any{"default": "allow", "rules": []any{map[string]any{"name": "no-chroot", "action": "deny", "target": map[string]any{"syscall": []any{"chroot"}}}}}}}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	backend := &goldenBackend{}
	controller, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := sandboxpolicy.NewSectionExporter(sandboxpolicy.SectionExporterOptions{Capacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app"}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, QOSClass: corev1.PodQOSBestEffort}})
	containers := &containercollection.ContainerCollection{}
	running := &containercollection.Container{CgroupID: 500, CgroupV2: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podother_uid.slice/cri-containerd-x.scope"}
	running.Runtime.ContainerID = "x"
	running.K8s.PodUID = "other-uid"
	containers.AddContainer(running)
	want := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice"
	s := &Service{Controller: controller, backend: backend, exporter: exporter, sectionExporter: sections, closeRuntime: func() error { return nil },
		options:  ServiceOptions{Dynamic: client, Kubernetes: kube, Containers: containers, NodeName: "node"},
		bindings: map[string]sandboxpolicy.Binding{}, done: make(chan struct{}), wake: make(chan struct{}, 1),
		scheduled: []sandboxpolicy.Binding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}},
		qos:       map[types.UID]corev1.PodQOSClass{"pod-uid": corev1.PodQOSBestEffort},
		podCgroupID: func(path string) (uint64, error) {
			if path != want {
				return 0, errors.New("no such cgroup")
			}
			return 77, nil
		},
		snapshot: func(context.Context) ([]sandboxpolicy.Binding, error) {
			return []sandboxpolicy.Binding{{Runtime: "containerd", ContainerID: "c1", CgroupID: 42, CgroupPath: "/pod/container", PID: 10, MountNamespace: 99, PodUID: "pod-uid", PodName: "pod", Namespace: "ns", ContainerName: "app", Kind: "regular"}}, nil
		}}
	step := func(name string, f func()) {
		backend.add("-- %s", name)
		f()
	}
	if err := controller.InitialSync(t.Context()); err != nil {
		t.Fatal(err)
	}
	step("bindPods", func() { s.bindPods(t.Context()) })
	s.inputEpoch.Add(1)
	step("bindPods", func() { s.bindPods(t.Context()) })
	step("pollPods", func() { s.pollPods(t.Context()) })
	backend.bindErr = errors.New("busy")
	step("bindPods (error)", func() { s.bindPods(t.Context()) })
	step("pollPods (error)", func() { s.pollPods(t.Context()) })
	backend.bindErr = nil
	step("refresh", func() { s.refresh(t.Context()) })
	step("refresh", func() { s.refresh(t.Context()) })
	step("Close", func() {
		if err := s.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	return backend.log
}

// gateOffGolden is gateOffScenario's log at HEAD 98c0a432 (before S3),
// recorded by running this file in a scratch copy of that commit
// (n2-evidence/s3/gateoff-golden-head.log).
const gateOffGolden = `-- bindPods
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
-- bindPods
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
-- pollPods
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
-- bindPods (error)
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
-- pollPods (error)
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
-- refresh
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
Replace c1 [policy-uid:enforce:priv=true]
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
Settle
-- refresh
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
Replace c1 [policy-uid:enforce:priv=true]
BindPods [pod-uid/ns/pod cgroup=77 path=/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice plan=[policy-uid:enforce:priv=true] started=false]
Settle
-- Close
Close`

// TestServiceStartGateOffMatchesHEADGolden: with the gate off, the backend
// gets exactly the calls it got at HEAD 98c0a432 (S3 review v1 LOW 8).
func TestServiceStartGateOffMatchesHEADGolden(t *testing.T) {
	got := strings.Join(gateOffScenario(t), "\n")
	if got != gateOffGolden {
		t.Fatalf("gate-off backend calls differ from HEAD 98c0a432:\n--- got\n%s\n--- HEAD\n%s", got, gateOffGolden)
	}
}
