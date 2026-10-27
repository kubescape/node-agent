package igbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

// Use the real controller and backend ownership maps. A controller fake keyed
// with the controller's own helper cannot detect mismatched identity domains.
type controllerIdentitySource struct{ leases []*fullTestLease }

func (s *controllerIdentitySource) Prepare(context.Context, sandboxpolicy.Binding) (FullBindingLease, error) {
	l := &fullTestLease{}
	s.leases = append(s.leases, l)
	return l, nil
}

type controllerIdentityInstance struct {
	fullTestInstance
	health          error
	checks          int
	holdUncommitted bool
	previousProgram *fullpolicy.KernelProgram
	aborts          int
	abortError      error
}

func (i *controllerIdentityInstance) Check(ctx context.Context) error {
	i.checks++
	return errors.Join(i.health, i.fullTestInstance.Check(ctx))
}

// Model a failed drain that leaves an uncommitted candidate staged. Resume
// would publish it, whereas AbortPending must preserve the active generation.
func (i *controllerIdentityInstance) Update(ctx context.Context, program *fullpolicy.KernelProgram) (fullruntime.PublicationResult, error) {
	if !i.holdUncommitted {
		return i.fullTestInstance.Update(ctx, program)
	}
	i.updates++
	i.previousProgram = i.program
	i.program = program
	header, _ := fullpolicy.Decode[fullpolicy.KernelHeader](program.Entries[0])
	i.pending = header.Generation
	return fullruntime.PublicationResult{}, errors.New("drain incomplete before commit")
}
func (i *controllerIdentityInstance) AbortPending(context.Context) error {
	i.aborts++
	if i.abortError != nil {
		return i.abortError
	}
	if i.pending != 0 && i.generation == i.pending {
		return errors.New("cannot abort committed publication")
	}
	i.pending = 0
	i.program = i.previousProgram
	i.previousProgram = nil
	return nil
}

type controllerIdentityEngine struct{ instances []*controllerIdentityInstance }

func (e *controllerIdentityEngine) Start(ctx context.Context, _ string, cfg FullStartConfig, emit func(RawFullVerdict)) (FullInstance, error) {
	lease, err := cfg.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	i := &controllerIdentityInstance{fullTestInstance: fullTestInstance{program: cfg.Program, lease: lease, emit: emit}}
	e.instances = append(e.instances, i)
	return i, nil
}

type controllerIdentityWriter struct{ report *api.SandboxPolicyNodeStatus }

func (w *controllerIdentityWriter) WriteStatus(_ context.Context, report *api.SandboxPolicyNodeStatus) error {
	w.report = report.DeepCopy()
	return nil
}

func controllerIdentityFixture(t *testing.T) (*sandboxpolicy.Controller, *FullBackend, *controllerIdentityEngine, *controllerIdentitySource, *controllerIdentityWriter, *fake.FakeDynamicClient, sandboxpolicy.Binding) {
	t.Helper()
	p := &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "ns", UID: "policy-uid", Generation: 1}, Spec: api.SandboxPolicySpec{PolicySpec: api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce, Exec: &api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{{Rule: api.Rule{Name: "shell", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/sh"}}}}}}}}}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"}, &unstructured.Unstructured{Object: raw})
	engine, source, writer := &controllerIdentityEngine{}, &controllerIdentitySource{}, &controllerIdentityWriter{}
	backend, err := NewFull(engine, source, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := sandboxpolicy.NewController(client, backend, nil, writer, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "id", CgroupPath: "/test", CgroupID: 19, PID: 20, MountNamespace: 21, PodUID: "pod-uid", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}
	if err := controller.SetBindings(context.Background(), []sandboxpolicy.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	if err := controller.InitialSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return controller, backend, engine, source, writer, client, binding
}

func TestControllerFullBackendPhysicalIdentityReplacement(t *testing.T) {
	changes := map[string]func(*sandboxpolicy.Binding){
		"pid":             func(b *sandboxpolicy.Binding) { b.PID++ },
		"mount-namespace": func(b *sandboxpolicy.Binding) { b.MountNamespace++ },
		"runtime":         func(b *sandboxpolicy.Binding) { b.Runtime = "cri-o" },
		"cgroup-path":     func(b *sandboxpolicy.Binding) { b.CgroupPath = "/replacement" },
	}
	for name, change := range changes {
		for _, failedRetirement := range []bool{false, true} {
			suffix := "/immediate"
			if failedRetirement {
				suffix = "/failed-retirement"
			}
			t.Run(name+suffix, func(t *testing.T) {
				c, b, e, s, w, _, old := controllerIdentityFixture(t)
				ctx := context.Background()
				next := old
				change(&next)
				first := e.instances[0]
				first.failStop = failedRetirement
				err := c.SetBindings(ctx, []sandboxpolicy.Binding{next})
				if failedRetirement {
					if err == nil || len(e.instances) != 1 || len(s.leases) != 1 || b.records[key(old)] == nil || !b.records[key(old)].retiring {
						t.Fatal("failed retirement lost ownership or admitted replacement", err)
					}
					if w.report.Status.Conditions[0].Status != metav1.ConditionFalse || len(w.report.Status.Conditions) != 1 {
						t.Fatal("failed retirement advertised confirmed protection")
					}
					if err := c.Reconcile(ctx); err == nil || len(e.instances) != 1 {
						t.Fatal("failed retry admitted replacement", err)
					}
					first.failStop = false
					err = c.Reconcile(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(e.instances) != 2 || len(s.leases) != 2 || s.leases[0].closed != 1 || s.leases[1].closed != 0 || b.records[key(old)] != nil || b.records[key(next)] == nil || len(b.records) != 1 {
					t.Fatal("physical replacement did not retire exactly the old owner")
				}
				current := e.instances[1]
				generation := current.Generation()
				result, err := b.Withdraw(ctx, old)
				if err != nil || !result.Committed || current.stops != 0 || s.leases[1].closed != 0 || b.records[key(next)] == nil {
					t.Fatal("stale old withdrawal touched replacement", result, err)
				}
				if err := c.Reconcile(ctx); err != nil || current.Generation() != generation || len(e.instances) != 2 || current.updates != 0 || w.report.Status.Conditions[0].Status != metav1.ConditionTrue {
					t.Fatal("replacement failed subsequent attestation", err)
				}
			})
		}
	}
}

func TestControllerFullBackendSnapshotFailureCannotAdvertiseDeadOwner(t *testing.T) {
	for _, configuration := range []bool{false, true} {
		name := "binding"
		if configuration {
			name = "configuration"
		}
		t.Run(name, func(t *testing.T) {
			c, b, e, s, w, client, binding := controllerIdentityFixture(t)
			ctx := context.Background()
			owner := e.instances[0]
			owner.health = errors.New("init exited / owner quarantined")
			fail := true
			checks := owner.checks
			if configuration {
				client.PrependReactor("list", "sandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
					if fail {
						return true, nil, errors.New("API unavailable")
					}
					return false, nil, nil
				})
				if err := c.InitialSync(ctx); err == nil {
					t.Fatal("configuration outage hidden")
				}
			} else if err := c.ReportBindingFailure(ctx, errors.New("discovery unavailable")); err == nil {
				t.Fatal("binding outage hidden")
			}
			if err := c.Reconcile(ctx); err == nil {
				t.Fatal("outage cleared prematurely")
			}
			if len(w.report.Status.Conditions) != 1 || w.report.Status.Conditions[0].Status != metav1.ConditionFalse || !w.report.Status.Stale {
				t.Fatal("dead owner advertised as confirmed last-good", w.report.Status)
			}
			if len(b.records) != 1 || len(e.instances) != 1 || owner.stops != 0 || owner.updates != 0 || s.leases[0].closed != 0 {
				t.Fatal("outage changed retained ownership")
			}
			if configuration && owner.checks != checks {
				t.Fatal("configuration freeze called backend")
			}
			if !configuration && owner.checks <= checks {
				t.Fatal("binding outage skipped last-good health attestation")
			}
			fail = false
			var err error
			if configuration {
				err = c.InitialSync(ctx)
			} else {
				err = c.SetBindings(ctx, []sandboxpolicy.Binding{binding})
			}
			if err == nil || len(w.report.Status.Conditions) != 1 {
				t.Fatal("fresh snapshot falsely recovered unhealthy owner", err)
			}
			owner.health = nil
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if len(w.report.Status.Conditions) != 2 || w.report.Status.Conditions[0].Status != metav1.ConditionTrue || len(e.instances) != 1 || owner.updates != 0 {
				t.Fatal("fresh healthy attestation failed to restore confirmed protection")
			}
		})
	}
}

func stageControllerUncommitted(t *testing.T, c *sandboxpolicy.Controller, client *fake.FakeDynamicClient, owner *controllerIdentityInstance) {
	t.Helper()
	ctx := context.Background()
	p, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Get(ctx, "policy", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.SetGeneration(p.GetGeneration() + 1)
	if err := unstructured.SetNestedField(p.Object, "allow", "spec", "exec", "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	owner.holdUncommitted = true
	c.ModifyHandler(ctx, p)
	if c.LastError() == nil || owner.pending == 0 || owner.generation == owner.pending {
		t.Fatal("test requires an uncommitted staged candidate")
	}
}

func TestControllerBindingFailureNeverResumesUncommittedCandidate(t *testing.T) {
	c, b, e, s, w, client, binding := controllerIdentityFixture(t)
	owner := e.instances[0]
	ctx := context.Background()
	oldGeneration, oldRevision := owner.generation, b.records[key(binding)].revision
	stageControllerUncommitted(t, c, client, owner)
	pending := owner.pending
	updates, resumes, aborts := owner.updates, owner.resumes, owner.aborts
	if err := c.ReportBindingFailure(ctx, errors.New("discovery unavailable")); err == nil {
		t.Fatal("outage hidden")
	}
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("outage unexpectedly cleared")
	}
	if owner.generation != oldGeneration || owner.pending != pending || b.records[key(binding)].revision != oldRevision || owner.updates != updates || owner.resumes != resumes || owner.aborts != aborts || len(e.instances) != 1 || len(s.leases) != 1 {
		t.Fatal("snapshot outage published or changed pending candidate")
	}
	if len(w.report.Status.Conditions) != 1 || w.report.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("uncommitted candidate advertised protection")
	}
	// A fresh authoritative snapshot may resume the still-desired candidate.
	owner.holdUncommitted = false
	if err := c.SetBindings(ctx, []sandboxpolicy.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	if owner.generation != pending || owner.resumes != resumes+1 || owner.updates != updates || len(e.instances) != 1 || w.report.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("authoritative recovery failed to finalize desired candidate")
	}
	checks := owner.checks
	if err := c.ReportBindingFailure(ctx, errors.New("discovery unavailable again")); err == nil {
		t.Fatal("outage hidden")
	}
	if owner.checks != checks+1 || owner.generation != pending || owner.resumes != resumes+1 || owner.updates != updates || len(w.report.Status.Conditions) != 2 {
		t.Fatal("healthy read-only attestation changed owner or failed to confirm retained revision")
	}
}
