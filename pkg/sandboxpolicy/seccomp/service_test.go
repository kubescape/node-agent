package seccomp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	nriapi "github.com/containerd/nri/pkg/api"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func privilegePolicy(name string, spec api.PolicySpec) *api.SandboxPolicy {
	return &api.SandboxPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agents", UID: types.UID(name), Generation: 1},
		Spec:       api.SandboxPolicySpec{Selector: api.PodPolicySelector{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}}, PolicySpec: spec},
	}
}

func agentPod(name string, labels map[string]string, mutate func(*corev1.Pod)) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agents", UID: types.UID(name + "-uid"), Labels: labels},
		Spec:   corev1.PodSpec{NodeName: "node-1", Containers: []corev1.Container{{Name: "main"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if mutate != nil {
		mutate(pod)
	}
	return pod
}

type harness struct {
	service *Service
	dynamic *dynamicfake.FakeDynamicClient
	errs    []error
}

func newHarness(t *testing.T, profilesDir string, pods []*corev1.Pod, policies ...*api.SandboxPolicy) *harness {
	t.Helper()
	var objects []runtime.Object
	for _, p := range policies {
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, &unstructured.Unstructured{Object: raw})
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList"}, objects...)
	kubeObjects := []runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "agents"}}}
	byName := map[string]*corev1.Pod{}
	for _, pod := range pods {
		kubeObjects = append(kubeObjects, pod)
		byName[pod.Name] = pod
	}
	h := &harness{dynamic: client}
	service, err := NewService(Options{
		Dynamic: client, Kubernetes: kubefake.NewSimpleClientset(kubeObjects...), NodeName: "node-1", ProfilesDir: profilesDir, Arch: "amd64",
		Pods:           func(_, name string) *corev1.Pod { return byName[name] },
		RuntimeDefault: func([]string) *specs.LinuxSeccomp { return runtimeDefaultFixture(false) },
		Contributes:    true,
		OnError:        func(err error) { h.errs = append(h.errs, err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.service = service
	service.refresh(context.Background())
	return h
}

func nriPod(pod *corev1.Pod) *nriapi.PodSandbox {
	return &nriapi.PodSandbox{Id: "sandbox-" + pod.Name, Name: pod.Name, Namespace: pod.Namespace, Uid: string(pod.UID), Labels: pod.Labels}
}

// unconfinedCtr is a container the runtime reports as Unconfined.
func unconfinedCtr(id, sandbox string) *nriapi.Container {
	return &nriapi.Container{Id: id, PodSandboxId: sandbox, Name: "main", Linux: &nriapi.LinuxContainer{SeccompProfile: &nriapi.SecurityProfile{ProfileType: nriapi.SecurityProfile_UNCONFINED}}}
}

func noUserns() api.PolicySpec {
	return privilegeSpec(api.ModeEnforce, api.ActionAllow, deny("no-userns", []string{"unshare"}, "CLONE_NEWUSER"), deny("no-mount", []string{"mount"}))
}

func TestCreateContainerInjectsOnlySelectedContainers(t *testing.T) {
	selected := agentPod("agent", map[string]string{"app": "agent"}, nil)
	other := agentPod("web", map[string]string{"app": "web"}, nil)
	h := newHarness(t, "", []*corev1.Pod{selected, other}, privilegePolicy("p", noUserns()))
	ctx := context.Background()

	adjust, _, err := h.service.CreateContainer(ctx, nriPod(selected), unconfinedCtr("c1", "sandbox-agent"))
	if err != nil || adjust == nil {
		t.Fatalf("adjust=%v err=%v errs=%v", adjust, err, h.errs)
	}
	policy := adjust.GetLinux().GetSeccompPolicy()
	if policy == nil || policy.DefaultAction != string(specs.ActAllow) || adjust.GetAnnotations()[AnnotationKey] == "" {
		t.Fatalf("adjustment: %+v", adjust)
	}
	names := map[string]bool{}
	for _, s := range policy.Syscalls {
		for _, n := range s.Names {
			names[n] = true
		}
	}
	for _, must := range []string{"unshare", "mount", "fsopen"} {
		if !names[must] {
			t.Errorf("profile misses %s", must)
		}
	}
	adjust, _, err = h.service.CreateContainer(ctx, nriPod(other), unconfinedCtr("c2", "sandbox-web"))
	if err != nil || adjust != nil {
		t.Fatalf("unselected pod must not be adjusted: %v %v", adjust, err)
	}
}

func TestPendingAfterPolicyChangeAndForOldContainers(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	ctx := context.Background()
	h.service.nriActive.Store(true)
	if _, _, err := h.service.CreateContainer(ctx, nriPod(pod), unconfinedCtr("c1", "sandbox-agent")); err != nil {
		t.Fatal(err)
	}
	h.service.refresh(ctx)
	if pending, _ := h.service.Contribute("p"); len(pending) != 0 {
		t.Fatalf("fresh container must not be pending: %v", pending)
	}

	// The policy gains a rule after the container started.
	updated := privilegePolicy("p", privilegeSpec(api.ModeEnforce, api.ActionAllow, deny("no-userns", []string{"unshare"}, "CLONE_NEWUSER"), deny("no-mount", []string{"mount"}), deny("no-bpf", []string{"bpf"})))
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(updated)
	if _, err := h.dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("agents").Update(ctx, &unstructured.Unstructured{Object: raw}, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.service.ModifyHandler(ctx, nil)
	h.service.refresh(ctx)
	pending, degraded := h.service.Contribute("p")
	if strings.Join(pending, ",") != "no-bpf,no-mount,no-userns" {
		t.Fatalf("pending: %v", pending)
	}
	if len(degraded) != 1 || degraded[0].Type != ConditionAppliesOnRestart || degraded[0].Message != "1 container(s): policy changed after the container started" {
		t.Fatalf("conditions: %+v", degraded)
	}

	// Containers that existed before the plugin registered have no annotation.
	if _, err := h.service.Synchronize(ctx, []*nriapi.PodSandbox{nriPod(pod)}, []*nriapi.Container{unconfinedCtr("old", "sandbox-agent")}); err != nil {
		t.Fatal(err)
	}
	h.service.refresh(ctx)
	_, degraded = h.service.Contribute("p")
	if len(degraded) == 0 || !strings.Contains(degraded[0].Message, "started before the policy") {
		t.Fatalf("conditions: %+v", degraded)
	}
}

func TestSkippedContainersAndUnsupportedRulesAreReported(t *testing.T) {
	privileged := true
	pod := agentPod("agent", map[string]string{"app": "agent"}, func(p *corev1.Pod) {
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &privileged}
	})
	spec := noUserns()
	spec.Privilege.Rules = append(spec.Privilege.Rules, api.PrivilegeRule{Rule: api.Rule{Name: "no-sysadmin", Action: api.ActionDeny}, Target: api.PrivilegeTarget{Capability: []string{"SYS_ADMIN"}}})
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", spec))
	ctx := context.Background()
	h.service.nriActive.Store(true)
	adjust, _, err := h.service.CreateContainer(ctx, nriPod(pod), unconfinedCtr("c1", "sandbox-agent"))
	if err != nil || adjust != nil {
		t.Fatalf("privileged container must keep its profile: %v %v", adjust, err)
	}
	h.service.refresh(ctx)
	_, degraded := h.service.Contribute("p")
	var reasons []string
	for _, d := range degraded {
		reasons = append(reasons, d.Type+":"+d.Message)
	}
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, ConditionAppliesOnRestart+":1 container(s): privileged container") || !strings.Contains(joined, ConditionUnsupported+":no-sysadmin: not a syscall target") {
		t.Fatalf("conditions:\n%s", joined)
	}
}

func TestFallbackWritesOptInProfileWithoutNRI(t *testing.T) {
	dir := t.TempDir()
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, dir, []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	_, degraded := h.service.Contribute("p")
	if len(degraded) == 0 || !strings.Contains(degraded[0].Message, "NRI unavailable") {
		t.Fatalf("conditions: %+v errs=%v", degraded, h.errs)
	}
	files, _ := filepath.Glob(filepath.Join(dir, FallbackDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("fallback files: %v", files)
	}
	reference := filepath.Join(FallbackDir, filepath.Base(files[0]))
	if !strings.Contains(degraded[0].Message, reference) {
		t.Fatalf("reason must name the profile: %s", degraded[0].Message)
	}
	// the pod sets no profile and the runtime did not report one: the file is
	// built on RuntimeDefault, never looser than what the kubelet may apply
	data, err := os.ReadFile(files[0])
	if err != nil || !strings.HasPrefix(filepath.Base(files[0]), "rd-") || !strings.Contains(string(data), `"defaultAction":"SCMP_ACT_ERRNO"`) {
		t.Fatalf("profile file %s: %s %v", files[0], data, err)
	}

	// A pod that references the file is protected and no longer pending.
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: &reference}}
	if _, err := h.service.options.Kubernetes.CoreV1().Pods("agents").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.service.podsListed = time.Time{}
	h.service.refresh(context.Background())
	if pending, _ := h.service.Contribute("p"); len(pending) != 0 {
		t.Fatalf("pending: %v", pending)
	}

	// Once NRI is back, the opted-in container has no annotation but is protected.
	h.service.nriActive.Store(true)
	if _, err := h.service.Synchronize(context.Background(), []*nriapi.PodSandbox{nriPod(pod)}, []*nriapi.Container{{Id: "c1", PodSandboxId: "sandbox-agent", Name: "main"}}); err != nil {
		t.Fatal(err)
	}
	h.service.refresh(context.Background())
	if pending, _ := h.service.Contribute("p"); len(pending) != 0 {
		t.Fatalf("opted-in container reported pending with NRI: %v", pending)
	}
}

func TestExecPolicyAddsRootBarrier(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce, Exec: &api.ExecSection{Default: api.ActionAllow}}
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("exec-only", spec))
	h.service.options.ExecEnforcement = true
	adjust, _, err := h.service.CreateContainer(context.Background(), nriPod(pod), unconfinedCtr("c1", "sandbox-agent"))
	if err != nil || adjust == nil {
		t.Fatalf("exec enforcement needs the root barrier: %v %v %v", adjust, err, h.errs)
	}
	names := map[string]bool{}
	for _, s := range adjust.GetLinux().GetSeccompPolicy().Syscalls {
		for _, n := range s.Names {
			names[n] = true
		}
	}
	for _, must := range []string{"chroot", "pivot_root", "setns", "unshare", "clone", "clone3"} {
		if !names[must] {
			t.Errorf("root barrier misses %s", must)
		}
	}
}

type fakeSeccompEvent struct {
	containerID, syscall, code, comm string
}

func (e fakeSeccompEvent) GetContainerID() string      { return e.containerID }
func (fakeSeccompEvent) GetEventType() utils.EventType { return utils.AuditSeccompEventType }
func (fakeSeccompEvent) GetNamespace() string          { return "agents" }
func (fakeSeccompEvent) GetPod() string                { return "agent" }
func (fakeSeccompEvent) GetTimestamp() igtypes.Time    { return 0 }
func (fakeSeccompEvent) HasDroppedEvents() bool        { return false }
func (fakeSeccompEvent) Release()                      {}
func (fakeSeccompEvent) GetContainer() string          { return "main" }
func (fakeSeccompEvent) GetPID() uint32                { return 42 }
func (e fakeSeccompEvent) GetComm() string {
	if e.comm != "" {
		return e.comm
	}
	return "unshare"
}
func (e fakeSeccompEvent) GetSyscall() string     { return e.syscall }
func (e fakeSeccompEvent) GetSeccompCode() string { return e.code }

type captureReceiver struct{ verdicts []Verdict }

func (c *captureReceiver) ReportSyscallVerdict(_ context.Context, v Verdict) error {
	c.verdicts = append(c.verdicts, v)
	return nil
}

func TestAuditSeccompEventsBecomeAttributedVerdicts(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	audited := deny("watch-bpf", []string{"bpf"})
	audited.Mode = api.RuleAudit
	spec := noUserns()
	spec.Privilege.Rules = append(spec.Privilege.Rules, audited)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", spec))
	receiver := &captureReceiver{}
	h.service.options.Receivers = maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]()
	h.service.options.Receivers.Set(utils.SyscallAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](receiver))
	ctx := context.Background()
	if _, _, err := h.service.CreateContainer(ctx, nriPod(pod), unconfinedCtr("c1", "sandbox-agent")); err != nil {
		t.Fatal(err)
	}

	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "mount", code: "SECCOMP_RET_ERRNO"})
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "unshare", code: "SECCOMP_RET_ERRNO"})
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "bpf", code: "SECCOMP_RET_LOG"})
	// not ours: another container, an unrelated syscall, an unknown action
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "other", syscall: "mount", code: "SECCOMP_RET_ERRNO"})
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "reboot", code: "SECCOMP_RET_ERRNO"})
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "mount", code: "SECCOMP_RET_KILL_PROCESS"})
	// runc during kubectl exec, retrying with the old mount API
	h.service.ReportEvent(utils.AuditSeccompEventType, fakeSeccompEvent{containerID: "c1", syscall: "open_tree", code: "SECCOMP_RET_ERRNO", comm: "runc:[2:INIT]"})

	if len(receiver.verdicts) != 3 {
		t.Fatalf("verdicts: %+v", receiver.verdicts)
	}
	mount, unshare, bpf := receiver.verdicts[0], receiver.verdicts[1], receiver.verdicts[2]
	if mount.Verdict != api.ActionDeny || mount.WouldDeny || !mount.MatchesComplete || len(mount.Matches) != 1 || mount.Matches[0].Rule != "no-mount" || mount.Matches[0].Origin != "catalog/G1" {
		t.Fatalf("mount: %+v", mount)
	}
	if unshare.MatchesComplete || len(unshare.Matches) != 1 || unshare.Matches[0].Flags != cloneNewUser {
		t.Fatalf("a flag rule match cannot be proven from the record: %+v", unshare)
	}
	if bpf.Verdict != api.ActionAllow || !bpf.WouldDeny || bpf.Mode != api.RuleAudit || bpf.Matches[0].Rule != "watch-bpf" {
		t.Fatalf("bpf: %+v", bpf)
	}
}

func TestInjectionUsesTheRuntimeProfileAsBase(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	ctr := &nriapi.Container{Id: "c1", PodSandboxId: "sandbox-agent", Name: "main", Linux: &nriapi.LinuxContainer{
		SeccompProfile: &nriapi.SecurityProfile{ProfileType: nriapi.SecurityProfile_RUNTIME_DEFAULT},
		SeccompPolicy:  nriapi.FromOCILinuxSeccomp(runtimeDefaultFixture(true)),
	}}
	adjust, _, err := h.service.CreateContainer(context.Background(), nriPod(pod), ctr)
	if err != nil || adjust == nil {
		t.Fatalf("adjust=%v err=%v errs=%v", adjust, err, h.errs)
	}
	policy := adjust.GetLinux().GetSeccompPolicy()
	if policy.DefaultAction != string(specs.ActErrno) {
		t.Fatalf("the runtime's default-deny base must be kept: %s", policy.DefaultAction)
	}
	for _, sc := range policy.Syscalls {
		if contains(sc.Names, "mount") && sc.Action == string(specs.ActAllow) {
			t.Fatalf("mount still allowed: %+v", sc)
		}
	}
}

func TestNoInjectionOnAnAssumedBase(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	h.service.nriActive.Store(true)
	// the runtime reports nothing and the pod sets no profile
	ctr := &nriapi.Container{Id: "c1", PodSandboxId: "sandbox-agent", Name: "main"}
	adjust, _, err := h.service.CreateContainer(context.Background(), nriPod(pod), ctr)
	if err != nil || adjust != nil {
		t.Fatalf("must not replace a profile it cannot see: %v %v", adjust, err)
	}
	h.service.refresh(context.Background())
	_, conditions := h.service.Contribute("p")
	if len(conditions) == 0 || !strings.Contains(conditions[0].Message, "runtime did not report") {
		t.Fatalf("conditions: %+v", conditions)
	}
}

func TestBuildErrorsAreReported(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	h.service.nriActive.Store(true)
	// a runtime base whose unshare rule cannot be narrowed by a flag
	base := runtimeDefaultFixture(false)
	base.Syscalls = append(base.Syscalls, specs.LinuxSyscall{Names: []string{"unshare"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 1, Value: 1, Op: specs.OpEqualTo}}})
	ctr := &nriapi.Container{Id: "c1", PodSandboxId: "sandbox-agent", Name: "main", Linux: &nriapi.LinuxContainer{
		SeccompProfile: &nriapi.SecurityProfile{ProfileType: nriapi.SecurityProfile_RUNTIME_DEFAULT},
		SeccompPolicy:  nriapi.FromOCILinuxSeccomp(base),
	}}
	if adjust, _, _ := h.service.CreateContainer(context.Background(), nriPod(pod), ctr); adjust != nil {
		t.Fatal("must not inject a profile it could not build")
	}
	h.service.refresh(context.Background())
	pending, conditions := h.service.Contribute("p")
	if len(pending) == 0 || len(conditions) == 0 || !strings.Contains(conditions[0].Message, "cannot build the profile") {
		t.Fatalf("pending %v conditions %+v", pending, conditions)
	}
}

func TestRootBarrierOnlyForEnforcedExecWithTheController(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	for name, tc := range map[string]struct {
		mode       api.PolicyMode
		controller bool
		want       bool
	}{
		"enforce with controller":    {api.ModeEnforce, true, true},
		"audit with controller":      {api.ModeAudit, true, false},
		"enforce without controller": {api.ModeEnforce, false, false},
	} {
		spec := api.PolicySpec{Containers: []string{"*"}, Mode: tc.mode, Exec: &api.ExecSection{Default: api.ActionAllow}}
		h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("exec-only", spec))
		h.service.options.ExecEnforcement = tc.controller
		adjust, _, _ := h.service.CreateContainer(context.Background(), nriPod(pod), unconfinedCtr("c1", "sandbox-agent"))
		if (adjust != nil) != tc.want {
			t.Errorf("%s: adjust=%v", name, adjust != nil)
		}
	}
}

func TestRuntimeSupportsSeccomp(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		want          bool
	}{
		{"containerd", "v2.3.4", true}, {"containerd", "2.2.0", true}, {"containerd", "v2.1.4", false},
		{"containerd", "1.7.30", false}, {"cri-o", "1.34.0", true}, {"cri-o", "1.33.2", false}, {"other", "9.9", false},
	} {
		if got, _ := runtimeSupportsSeccomp(tc.name, tc.version); got != tc.want {
			t.Errorf("%s %s: got %v", tc.name, tc.version, got)
		}
	}
}

func TestStopForgetsTheContainer(t *testing.T) {
	pod := agentPod("agent", map[string]string{"app": "agent"}, nil)
	h := newHarness(t, "", []*corev1.Pod{pod}, privilegePolicy("p", noUserns()))
	if _, err := h.service.Synchronize(context.Background(), []*nriapi.PodSandbox{nriPod(pod)}, []*nriapi.Container{unconfinedCtr("old", "sandbox-agent")}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.StopContainer(context.Background(), nriPod(pod), unconfinedCtr("old", "sandbox-agent")); err != nil {
		t.Fatal(err)
	}
	h.service.refresh(context.Background())
	if pending, _ := h.service.Contribute("p"); len(pending) != 0 {
		t.Fatalf("a stopped container must not stay pending: %v", pending)
	}
}

func TestBoundedKeepsRunes(t *testing.T) {
	text := strings.Repeat("é", api.MaxStatusDiagnosticLength)
	got := bounded(text)
	if len(got) > api.MaxStatusDiagnosticLength || !utf8.ValidString(got) {
		t.Fatalf("len %d valid %v", len(got), utf8.ValidString(got))
	}
}
