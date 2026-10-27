package sandboxpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

type fakeBackend struct {
	protectionUnconfirmed        bool
	attestations, cleanupRetries int
	cleanup                      map[string]bool
	postCommit                   bool
	withdrawPostCommit           bool
	plans                        map[string]Plan
	replacements, withdrawals    int
	fail                         bool
}

func (b *fakeBackend) Replace(_ context.Context, binding Binding, plan Plan) (ReplaceResult, error) {
	key := bindingKey(binding)
	if b.cleanup == nil {
		b.cleanup = make(map[string]bool)
	}
	current, exists := b.plans[key]
	same := exists && current.Revision == plan.Revision
	if same {
		b.attestations++
	} else {
		b.replacements++
	}
	if b.fail {
		return ReplaceResult{ProtectionUnconfirmed: b.protectionUnconfirmed}, errors.New("candidate failed")
	}
	result := ReplaceResult{Committed: true, ActiveRevision: plan.Revision, ProtectionUnconfirmed: b.protectionUnconfirmed}
	if same {
		if b.protectionUnconfirmed {
			return result, errors.New("instance externally stopped")
		}
		if b.cleanup[key] {
			b.cleanupRetries++
			if b.postCommit {
				return result, errors.New("retirement failed after commit")
			}
			delete(b.cleanup, key)
		}
		return result, nil
	}
	b.plans[key] = plan
	if b.protectionUnconfirmed {
		return result, errors.New("instance externally stopped")
	}
	if b.postCommit {
		b.cleanup[key] = true
		return result, errors.New("retirement failed after commit")
	}
	return result, nil
}

func (b *fakeBackend) Attest(_ context.Context, binding Binding, revision string) error {
	b.attestations++
	key := bindingKey(binding)
	if b.fail || b.protectionUnconfirmed || b.cleanup[key] || b.plans[key].Revision != revision {
		return errors.New("retained revision protection unconfirmed")
	}
	return nil
}

func (b *fakeBackend) Withdraw(_ context.Context, binding Binding) (WithdrawResult, error) {
	b.withdrawals++
	if b.fail {
		return WithdrawResult{ProtectionUnconfirmed: b.protectionUnconfirmed}, errors.New("withdraw failed")
	}
	delete(b.plans, bindingKey(binding))
	if b.withdrawPostCommit {
		return WithdrawResult{Committed: true}, errors.New("withdraw cleanup failed after commit")
	}
	return WithdrawResult{Committed: true}, nil
}

type fakeWriter struct {
	reports map[string]*api.SandboxPolicyNodeStatus
	fail    bool
}

func (w *fakeWriter) WriteStatus(_ context.Context, r *api.SandboxPolicyNodeStatus) error {
	if w.fail {
		return errors.New("status unavailable")
	}
	w.reports[string(r.Spec.PolicyRef.UID)] = r.DeepCopy()
	return nil
}
func policy(name, namespace string) *api.SandboxPolicy {
	return &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(name), Generation: 1}, Spec: api.SandboxPolicySpec{PolicySpec: execSpec()}}
}
func binding() Binding {
	return Binding{ContainerID: "container", CgroupID: 12, PodUID: "pod", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular", PodLabels: map[string]string{"app": "test"}, NamespaceLabels: map[string]string{"team": "red"}}
}
func setup(t *testing.T, objects ...runtime.Object) (*Controller, *fakeBackend, *fakeWriter, *fake.FakeDynamicClient) {
	t.Helper()
	scheme := runtime.NewScheme()
	var seeded []runtime.Object
	for _, obj := range objects {
		if _, isClasses := obj.(*api.SandboxPolicyClasses); !isClasses {
			raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
			if err != nil {
				t.Fatal(err)
			}
			seeded = append(seeded, &unstructured.Unstructured{Object: raw})
		}
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{PolicyGVR: "SandboxPolicyList", ClusterPolicyGVR: "ClusterSandboxPolicyList", ClassesGVR: "SandboxPolicyClassesList", NodeStatusGVR: "SandboxPolicyNodeStatusList"}, seeded...)
	for _, obj := range objects {
		if classes, ok := obj.(*api.SandboxPolicyClasses); ok {
			raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(classes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Resource(ClassesGVR).Create(context.Background(), &unstructured.Unstructured{Object: raw}, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	backend := &fakeBackend{plans: make(map[string]Plan)}
	writer := &fakeWriter{reports: make(map[string]*api.SandboxPolicyNodeStatus)}
	controller, err := NewController(client, backend, nil, writer, Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	return controller, backend, writer, client
}

func TestInitialSyncUpdateLastGoodAndWithdrawal(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if b.replacements != 1 {
		t.Fatalf("initial replacements %d", b.replacements)
	}
	p.ResourceVersion = "2"
	p.Status.ObservedGeneration = 1
	c.ModifyHandler(ctx, p)
	if b.replacements != 1 {
		t.Fatal("status-only reload")
	}
	original := b.plans[bindingKey(binding())].Revision
	p.Generation = 2
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/new"}
	b.fail = true
	c.ModifyHandler(ctx, p)
	if c.LastError() == nil || b.plans[bindingKey(binding())].Revision != original {
		t.Fatal("failed revision lost last-good")
	}
	report := w.reports["policy"]
	if report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.ObservedGeneration != 2 || !report.Status.Stale || !strings.Contains(report.Status.Conditions[0].Message, "last-good") {
		t.Fatalf("misleading report: %+v", report.Status)
	}
	b.fail = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b.plans[bindingKey(binding())].Revision == original {
		t.Fatal("retry did not install")
	}
	p.Generation = 3
	p.Spec.Mode = api.ModeOff
	c.ModifyHandler(ctx, p)
	if len(b.plans) != 0 || b.withdrawals != 1 {
		t.Fatal("off did not withdraw")
	}
	p.Generation = 4
	p.Spec.Mode = api.ModeEnforce
	c.ModifyHandler(ctx, p)
	c.DeleteHandler(ctx, p)
	if len(b.plans) != 0 || b.withdrawals != 2 {
		t.Fatal("delete did not withdraw")
	}
}

func TestSelectionAndChurn(t *testing.T) {
	ctx := context.Background()
	p := policy("namespaced", "other")
	cluster := &api.ClusterSandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "ClusterSandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "cluster", Generation: 1}, Spec: api.ClusterSandboxPolicySpec{Selector: api.ClusterPolicySelector{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}, NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}}, PolicySpec: execSpec()}}
	c, b, w, _ := setup(t, p, cluster)
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	regular := binding()
	init := regular
	init.ContainerID = "init"
	init.CgroupID = 13
	init.Kind = "init"
	if err := c.SetBindings(ctx, []Binding{regular, init}); err != nil {
		t.Fatal(err)
	}
	if len(b.plans) != 1 || len(b.plans[bindingKey(regular)].Policies) != 1 || b.plans[bindingKey(regular)].Policies[0].Identity.UID != "cluster" {
		t.Fatalf("incorrect selection: %+v", b.plans)
	}
	if w.reports["cluster"].Namespace != "agent" || w.reports["namespaced"].Namespace != "other" {
		t.Fatal("incorrect report namespace")
	}
	regular.NamespaceLabels["team"] = "blue"
	if err := c.SetBindings(ctx, []Binding{regular}); err != nil {
		t.Fatal(err)
	}
	if len(b.plans) != 0 {
		t.Fatal("namespace label change did not withdraw")
	}
	regular.NamespaceLabels["team"] = "red"
	if err := c.SetBindings(ctx, []Binding{regular}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBindings(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(b.plans) != 0 {
		t.Fatal("container deletion did not withdraw")
	}
}

func TestInvalidRevisionDoesNotWithdrawAndExplicitDeleteDoes(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	other := policy("other", "ns")
	c, b, _, _ := setup(t, p, other)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	original := b.plans[bindingKey(binding())].Revision
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: raw}
	u.SetGeneration(2)
	if err := unstructured.SetNestedField(raw, true, "spec", "unknownPredicate"); err != nil {
		t.Fatal(err)
	}
	c.ModifyHandler(ctx, u)
	if c.LastError() == nil || b.plans[bindingKey(binding())].Revision != original {
		t.Fatal("unknown field was dropped or last-good lost")
	}
	c.DeleteHandler(ctx, other)
	current := b.plans[bindingKey(binding())]
	if len(current.Policies) != 1 || current.Policies[0].Identity.UID != "policy" {
		t.Fatalf("explicit deletion retained behind unrelated invalid revision: %+v", current)
	}
}

func TestRelistFailurePreservesSnapshotAndStatusFailureVisible(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, client := setup(t, p)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	client.PrependReactor("list", "clustersandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("disconnected") })
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("hidden relist failure")
	}
	if len(b.plans) != 1 {
		t.Fatal("partial snapshot withdrawn")
	}
	w.fail = true
	if err := c.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "status unavailable") {
		t.Fatal("hidden status write loss")
	}
}

func TestClassChangesAndStaleDelete(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	p.Spec.Exec.Rules[0].Target.PathClass = []string{"tools"}
	classes := &api.SandboxPolicyClasses{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyClasses"}, ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "classes", Generation: 1}, Spec: api.PolicyClasses{PathClasses: map[string][]string{"tools": {"/bin/tool"}}}}
	c, b, _, _ := setup(t, p, classes)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	original := b.plans[bindingKey(binding())].Revision
	classes.Generation = 2
	classes.Spec.PathClasses["tools"] = []string{"/bin/next"}
	c.ModifyHandler(ctx, classes)
	if b.plans[bindingKey(binding())].Revision == original {
		t.Fatal("class update did not reload")
	}
	before := b.plans[bindingKey(binding())].Revision
	c.DeleteHandler(ctx, classes)
	if c.LastError() == nil || b.plans[bindingKey(binding())].Revision != before {
		t.Fatal("missing class weakened policy")
	}
	stale := p.DeepCopy()
	stale.UID = "old-uid"
	c.DeleteHandler(ctx, stale)
	if len(b.plans) != 1 {
		t.Fatal("stale delete removed newer policy")
	}
}

func TestProfileRefreshAndRejectedBinding(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	p.Spec.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "profile"}, Include: []string{"execs"}}}
	c, b, w, _ := setup(t, p)
	path := "/bin/initial"
	missing := false
	c.resolver = resolverFunc(func(context.Context, string, string, string) ([]api.ExecRule, error) {
		if missing {
			return nil, errors.New("missing profile")
		}
		return []api.ExecRule{{Rule: api.Rule{Name: "profile", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{path}}}}}, nil
	})
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	original := b.plans[bindingKey(binding())].Revision
	path = "/bin/changed"
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	changed := b.plans[bindingKey(binding())].Revision
	if original == changed {
		t.Fatal("profile update did not recompile")
	}
	missing = true
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("missing profile accepted")
	}
	if b.plans[bindingKey(binding())].Revision != changed {
		t.Fatal("profile loss removed last-good")
	}
	incomplete := binding()
	incomplete.CgroupID = 0
	if err := c.SetBindings(ctx, []Binding{incomplete}); err == nil {
		t.Fatal("incomplete binding accepted")
	}
	if len(b.plans) != 1 || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("failed binding barrier did not retain/report")
	}
}

func TestOutdatedGenerationAndMalformedSelection(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, _, _ := setup(t, p)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	p.Generation = 3
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/latest"}
	c.ModifyHandler(ctx, p)
	latest := b.plans[bindingKey(binding())].Revision
	old := p.DeepCopy()
	old.Generation = 2
	old.Spec.Mode = api.ModeOff
	c.ModifyHandler(ctx, old)
	if b.plans[bindingKey(binding())].Revision != latest {
		t.Fatal("stale revision changed enforcement")
	}
	p.Generation = 4
	p.Spec.Containers = nil
	c.ModifyHandler(ctx, p)
	if c.LastError() == nil || b.plans[bindingKey(binding())].Revision != latest {
		t.Fatal("malformed selector authorized withdrawal")
	}
}

func TestPostCommitFailureTracksActualRevisionAndRetriesCleanup(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	previous := b.plans[bindingKey(binding())].Revision
	b.postCommit = true
	p.Generation = 2
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/new"}
	c.ModifyHandler(ctx, p)
	current := b.plans[bindingKey(binding())]
	if current.Revision == previous || c.active[bindingKey(binding())].plan.Revision != current.Revision || !c.active[bindingKey(binding())].cleanupPending {
		t.Fatal("committed failure misreported as rollback")
	}
	report := w.reports["policy"]
	if report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.Conditions[0].Reason != "CleanupPending" || report.Status.Stale {
		t.Fatalf("incorrect committed failure status: %+v", report.Status)
	}
	if len(report.Status.Conditions) != 2 || !strings.Contains(report.Status.Conditions[1].Message, current.Policies[0].Revision) {
		t.Fatal("actual active revision missing")
	}
	replacements := b.replacements
	b.postCommit = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b.replacements != replacements || b.cleanupRetries != 1 || c.active[bindingKey(binding())].cleanupPending || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("cleanup retry did not converge")
	}
	if b.plans[bindingKey(binding())].Revision != current.Revision {
		t.Fatal("cleanup retry changed desired revision")
	}
}

func TestWithdrawalCommitAndCleanupBarrier(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	p.Generation = 2
	p.Spec.Mode = api.ModeOff
	b.fail = true
	c.ModifyHandler(ctx, p)
	if len(c.active) != 1 || len(b.plans) != 1 || len(c.withdrawals) != 0 {
		t.Fatal("precommit failure discarded last-good")
	}
	b.fail = false
	b.withdrawPostCommit = true
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("hidden postcommit failure")
	}
	if len(c.active) != 0 || len(b.plans) != 0 || len(c.withdrawals) != 1 {
		t.Fatal("committed removal still reported active or cleanup forgotten")
	}
	report := w.reports["policy"]
	if report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.Conditions[0].Reason != "WithdrawalCleanupPending" || strings.Contains(report.Status.Conditions[0].Message, "last-good") || len(report.Status.Conditions) != 1 {
		t.Fatalf("removed protection falsely reported: %+v", report.Status)
	}
	replacements := b.replacements
	// Re-enable while retirement is still pending: no new candidate may be placed
	// where a later retry could accidentally withdraw it.
	p.Generation = 3
	p.Spec.Mode = api.ModeEnforce
	c.ModifyHandler(ctx, p)
	if b.replacements != replacements || len(c.active) != 0 || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("replacement bypassed cleanup barrier")
	}
	b.fail = true
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("retry failure hidden")
	}
	if len(c.active) != 0 || len(c.withdrawals) != 1 {
		t.Fatal("failed retry resurrected withdrawn enforcement")
	}
	b.fail = false
	b.withdrawPostCommit = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.withdrawals) != 0 || len(c.active) != 1 || b.replacements != replacements+1 || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("cleanup/re-enable did not converge")
	}
}

func TestContainerDeletionPostCommitCleanup(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	b.withdrawPostCommit = true
	if err := c.SetBindings(ctx, nil); err == nil {
		t.Fatal("container cleanup failure hidden")
	}
	if len(c.active) != 0 || len(c.withdrawals) != 1 || w.reports["policy"].Status.Conditions[0].Reason != "WithdrawalCleanupPending" {
		t.Fatal("container removal falsely remains protected")
	}
	withdrawals := b.withdrawals
	b.withdrawPostCommit = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b.withdrawals != withdrawals+1 || len(c.withdrawals) != 0 || len(c.active) != 0 || len(b.plans) != 0 {
		t.Fatal("deleted binding cleanup did not converge")
	}
}

func TestReportBindingFailurePersistsUntilAuthoritativeSnapshot(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	revision := b.plans[bindingKey(binding())].Revision
	if err := c.ReportBindingFailure(ctx, errors.New("runtime discovery barrier incomplete")); err == nil {
		t.Fatal("binding barrier failure hidden")
	}
	if len(c.bindings) != 1 || len(c.active) != 1 || b.plans[bindingKey(binding())].Revision != revision || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("binding failure withdrew snapshot or reported Ready")
	}
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("periodic reconcile cleared failed snapshot barrier")
	}
	if w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionFalse || len(b.plans) != 1 {
		t.Fatal("periodic reconcile lost NotReady or enforcement")
	}
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionTrue || c.LastError() != nil || b.plans[bindingKey(binding())].Revision != revision {
		t.Fatal("valid snapshot did not clear barrier while preserving revision")
	}
}

func TestConfigurationFailureBarrierSurvivesOtherReconciliation(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, client := setup(t, p)
	first := binding()
	if err := c.SetBindings(ctx, []Binding{first}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	revision := b.plans[bindingKey(first)].Revision
	replaces := b.replacements
	fail := true
	client.PrependReactor("list", "clustersandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, errors.New("configuration API disconnected")
		}
		return false, nil, nil
	})
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("hidden configuration snapshot failure")
	}
	report := w.reports["policy"]
	if report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.Conditions[0].Reason != "ConfigurationUnavailable" || !report.Status.Stale {
		t.Fatal("configuration loss not reported")
	}
	second := first
	second.ContainerID = "new-container"
	second.CgroupID++
	if err := c.SetBindings(ctx, []Binding{first, second}); err == nil {
		t.Fatal("new runtime snapshot cleared configuration barrier")
	}
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("periodic reconcile cleared configuration barrier")
	}
	// Delayed change/delete events do not make a partial configuration current.
	changed := p.DeepCopy()
	changed.Generation++
	changed.Spec.Mode = api.ModeOff
	c.ModifyHandler(ctx, changed)
	c.DeleteHandler(ctx, p)
	if c.LastError() == nil || b.replacements != replaces || b.withdrawals != 0 || len(b.plans) != 1 || b.plans[bindingKey(first)].Revision != revision {
		t.Fatal("stale/partial config authorized transition")
	}
	if w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatal("watch event cleared NotReady")
	}
	fail = false
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.plans) != 2 || b.replacements != replaces+1 || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("coherent snapshot did not recover latest bindings")
	}
}

func TestConfigurationFailureDefersWithdrawalUntilRecovery(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, _, client := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	fail := true
	client.PrependReactor("list", "sandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, errors.New("list failed")
		}
		return false, nil, nil
	})
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("hidden failure")
	}
	if err := c.SetBindings(ctx, nil); err == nil {
		t.Fatal("empty binding snapshot cleared barrier")
	}
	if b.withdrawals != 0 || len(b.plans) != 1 {
		t.Fatal("withdrawal used incomplete configuration")
	}
	fail = false
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	if b.withdrawals != 1 || len(b.plans) != 0 {
		t.Fatal("recovery did not apply authoritative disappearance")
	}
}

func TestBindingSelectorUsesPolicySelectionWithoutObserverExemptions(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	p.Spec.Selector.PodSelector.MatchLabels = map[string]string{"app": "test"}
	c, _, _, _ := setup(t, p)
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	selected := c.BindingSelector()
	b := binding()
	if !selected(b) {
		t.Fatal("matching regular container not selected")
	}
	b.PodName = "node-agent-own"
	if !selected(b) {
		t.Fatal("inferred agent exemption")
	}
	b.Namespace = "other"
	if selected(b) {
		t.Fatal("namespaced policy escaped namespace")
	}
	b = binding()
	b.Kind = "init"
	if selected(b) {
		t.Fatal("wildcard selected init container")
	}
	b = binding()
	b.PodLabels = map[string]string{"app": "other"}
	if selected(b) {
		t.Fatal("pod labels ignored")
	}
	p.Generation++
	p.Spec.Mode = api.ModeOff
	c.ModifyHandler(ctx, p)
	if c.BindingSelector()(binding()) {
		t.Fatal("off policy still requires runtime discovery")
	}
	if !selected(binding()) {
		t.Fatal("selector closure aliased mutable controller configuration")
	}
	p.Generation++
	p.Spec.Mode = api.ModeEnforce
	c.ModifyHandler(ctx, p)
	c.DeleteHandler(ctx, p)
	if c.BindingSelector()(binding()) {
		t.Fatal("deleted policy still selects")
	}
}

func TestBindingSelectorClusterAndInvalidConservatism(t *testing.T) {
	ctx := context.Background()
	cluster := &api.ClusterSandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "ClusterSandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: "cluster", UID: "cluster", Generation: 1}, Spec: api.ClusterSandboxPolicySpec{Selector: api.ClusterPolicySelector{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}}, PolicySpec: execSpec()}}
	c, _, _, _ := setup(t, cluster)
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	b := binding()
	if !c.BindingSelector()(b) {
		t.Fatal("cluster selector not applied")
	}
	b.NamespaceLabels = map[string]string{"team": "blue"}
	if c.BindingSelector()(b) {
		t.Fatal("cluster namespace labels ignored")
	}
	cluster.Generation++
	cluster.Spec.Containers = nil
	c.ModifyHandler(ctx, cluster)
	b.Kind = "ephemeral"
	b.Namespace = "other"
	b.PodLabels = nil
	if !c.BindingSelector()(b) {
		t.Fatal("invalid cluster policy did not conservatively retain discovery")
	}
	c.DeleteHandler(ctx, cluster)
	p := policy("invalid", "ns")
	p.Spec.Containers = nil
	c.AddHandler(ctx, p)
	b.Namespace = "ns"
	if !c.BindingSelector()(b) {
		t.Fatal("invalid namespaced policy not conservative")
	}
	b.Namespace = "other"
	if c.BindingSelector()(b) {
		t.Fatal("invalid namespaced policy escaped owner namespace")
	}
}

type historyStatusWriter struct {
	reports []*api.SandboxPolicyNodeStatus
}

func (w *historyStatusWriter) WriteStatus(_ context.Context, report *api.SandboxPolicyNodeStatus) error {
	w.reports = append(w.reports, report.DeepCopy())
	return nil
}

func TestRefreshNeverReportsReadyBeforeBindingSnapshot(t *testing.T) {
	ctx := context.Background()
	p := policy("new-policy", "ns")
	c, b, _, _ := setup(t, p)
	history := &historyStatusWriter{}
	c.writer = history
	err := c.Refresh(ctx, func(_ context.Context, selected func(Binding) bool) ([]Binding, error) {
		if !selected(binding()) {
			t.Fatal("snapshot did not use newly fetched policy selectors")
		}
		if len(history.reports) != 0 || b.replacements != 0 {
			t.Fatal("configuration was reconciled before discovery barrier")
		}
		return nil, errors.New("selected ignored workload unavailable")
	})
	if err == nil || len(history.reports) == 0 || b.replacements != 0 {
		t.Fatal("failed new binding was not rejected/reported")
	}
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("InitialSync cleared failed binding barrier")
	}
	changed := p.DeepCopy()
	changed.Generation = 2
	changed.Spec.Exec.Rules[0].Target.Path = []string{"/bin/updated"}
	c.ModifyHandler(ctx, changed)
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("reconcile cleared failed binding barrier")
	}
	for _, r := range history.reports {
		if r.Spec.PolicyRef.UID == p.UID && r.Status.Conditions[0].Status != metav1.ConditionFalse {
			t.Fatalf("unavailable desired policy reported Ready: %+v", r.Status)
		}
	}
	if b.replacements != 0 {
		t.Fatal("stale runtime snapshot installed changed policy")
	}
	snapshotComplete := false
	if err := c.Refresh(ctx, func(_ context.Context, selected func(Binding) bool) ([]Binding, error) {
		if !selected(binding()) {
			t.Fatal("recovery selectors lost")
		}
		snapshotComplete = true
		return []Binding{binding()}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !snapshotComplete || b.replacements != 1 || history.reports[len(history.reports)-1].Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("complete snapshot failed to authorize Ready")
	}
}

func TestRefreshSelectsCandidateConfigurationAtomically(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	p.Spec.Selector.PodSelector.MatchLabels = map[string]string{"app": "old"}
	c, b, _, client := setup(t, p)
	old := binding()
	old.PodLabels = map[string]string{"app": "old"}
	if err := c.Refresh(ctx, func(_ context.Context, selected func(Binding) bool) ([]Binding, error) {
		if !selected(old) {
			t.Fatal("initial selector")
		}
		return []Binding{old}, nil
	}); err != nil {
		t.Fatal(err)
	}
	revision := b.plans[bindingKey(old)].Revision
	p.Generation = 2
	p.Spec.Selector.PodSelector.MatchLabels = map[string]string{"app": "new"}
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/new"}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(PolicyGVR).Namespace("ns").Update(ctx, &unstructured.Unstructured{Object: raw}, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	current := old
	current.PodLabels = map[string]string{"app": "new"}
	history := &historyStatusWriter{}
	c.writer = history
	if err := c.Refresh(ctx, func(_ context.Context, selected func(Binding) bool) ([]Binding, error) {
		if selected(old) || !selected(current) {
			t.Fatal("resolver used previous configuration selectors")
		}
		if b.plans[bindingKey(old)].Revision != revision || len(history.reports) != 0 {
			t.Fatal("candidate applied before matching snapshot completed")
		}
		return []Binding{current}, nil
	}); err != nil {
		t.Fatal(err)
	}
	plan := b.plans[bindingKey(current)]
	if plan.Revision == revision || plan.Policies[0].Identity.Generation != 2 || plan.Policies[0].Exec.Rules[0].Target.Path[0] != "/bin/new" || len(history.reports) != 1 || history.reports[0].Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("candidate configuration/bindings not committed together")
	}
}

func TestRefreshBindingFailureAllowsOnlyExplicitOffAndDeletion(t *testing.T) {
	ctx := context.Background()
	p := policy("off", "ns")
	other := policy("retained", "ns")
	c, b, _, client := setup(t, p, other)
	success := func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{binding()}, nil }
	failure := func(context.Context, func(Binding) bool) ([]Binding, error) {
		return nil, errors.New("binding snapshot incomplete")
	}
	if err := c.Refresh(ctx, success); err != nil {
		t.Fatal(err)
	}
	p.Generation = 2
	p.Spec.Mode = api.ModeOff
	other.Generation = 2
	other.Spec.Exec.Rules[0].Target.Path = []string{"/bin/must-not-install"}
	for _, object := range []*api.SandboxPolicy{p, other} {
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Resource(PolicyGVR).Namespace("ns").Update(ctx, &unstructured.Unstructured{Object: raw}, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Refresh(ctx, failure); err == nil {
		t.Fatal("failure hidden")
	}
	plan := b.plans[bindingKey(binding())]
	if len(plan.Policies) != 1 || plan.Policies[0].Identity.UID != "retained" || plan.Policies[0].Identity.Generation != 1 || plan.Policies[0].Exec.Rules[0].Target.Path[0] != "/bin/sh" {
		t.Fatal("failed snapshot either retained explicit off or installed revised rules")
	}
	replacements := b.replacements
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("config-only sync cleared binding barrier")
	}
	if b.replacements != replacements {
		t.Fatal("config-only sync installed revised plan")
	}
	if err := client.Resource(PolicyGVR).Namespace("ns").Delete(ctx, "retained", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(ctx, failure); err == nil {
		t.Fatal("failure hidden after delete")
	}
	if len(b.plans) != 0 || b.withdrawals != 1 {
		t.Fatal("authoritative deletion did not withdraw exact old binding")
	}
}

func TestRefreshConfigurationFailureDoesNotResolvePartialSelectors(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, _, client := setup(t, p)
	resolver := func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{binding()}, nil }
	if err := c.Refresh(ctx, resolver); err != nil {
		t.Fatal(err)
	}
	original := b.plans[bindingKey(binding())].Revision
	client.PrependReactor("list", "sandboxpolicyclasses", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("classes unavailable")
	})
	invoked := false
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) { invoked = true; return nil, nil }); err == nil {
		t.Fatal("partial configuration accepted")
	}
	if invoked || b.plans[bindingKey(binding())].Revision != original || b.withdrawals != 0 {
		t.Fatal("partial config invoked resolver or altered last-good")
	}
}

func TestFailedBindingSnapshotDefersCommittedOffCleanupUntilRecovery(t *testing.T) {
	ctx := context.Background()
	p := policy("off", "ns")
	other := policy("retained", "ns")
	c, b, _, client := setup(t, p, other)
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) { return []Binding{binding()}, nil }); err != nil {
		t.Fatal(err)
	}
	p.Generation = 2
	p.Spec.Mode = api.ModeOff
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(PolicyGVR).Namespace("ns").Update(ctx, &unstructured.Unstructured{Object: raw}, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	b.postCommit = true
	if err := c.Refresh(ctx, func(context.Context, func(Binding) bool) ([]Binding, error) {
		return nil, errors.New("discovery incomplete")
	}); err == nil {
		t.Fatal("failure hidden")
	}
	current := c.active[bindingKey(binding())]
	if !current.cleanupPending || len(current.plan.Policies) != 1 {
		t.Fatal("partial withdrawal commit not tracked")
	}
	replacements := b.replacements
	b.postCommit = false
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("cleanup incorrectly cleared binding barrier")
	}
	after := c.active[bindingKey(binding())]
	if b.replacements != replacements || b.cleanupRetries != 0 || !after.cleanupPending || !after.protectionUnconfirmed || after.plan.Revision != current.plan.Revision {
		t.Fatal("failed binding snapshot resumed pending publication")
	}
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	after = c.active[bindingKey(binding())]
	if b.cleanupRetries != 1 || after.cleanupPending || after.protectionUnconfirmed || after.plan.Revision != current.plan.Revision {
		t.Fatal("fresh binding snapshot did not finalize committed cleanup")
	}
}

func TestUnconfirmedProtectionIsNotReportedAsLastGood(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	b.protectionUnconfirmed = true
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("unchanged revision did not re-attest health")
	}
	current := c.active[bindingKey(binding())]
	report := w.reports["policy"]
	if !current.protectionUnconfirmed || report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.Conditions[0].Reason != "ProtectionUnconfirmed" || strings.Contains(report.Status.Conditions[0].Message, "last-good") || len(report.Status.Conditions) != 1 {
		t.Fatalf("unknown protection reported as active/last-good: %+v", report.Status)
	}
	b.fail = true
	p.Generation = 2
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/new"}
	c.ModifyHandler(ctx, p)
	if !c.active[bindingKey(binding())].protectionUnconfirmed || w.reports["policy"].Status.Conditions[0].Reason != "ProtectionUnconfirmed" {
		t.Fatal("rejected candidate hid prior loss")
	}
	b.fail = false
	b.protectionUnconfirmed = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if c.active[bindingKey(binding())].protectionUnconfirmed || w.reports["policy"].Status.Conditions[0].Status != metav1.ConditionTrue || len(w.reports["policy"].Status.Conditions) != 2 {
		t.Fatal("confirmed replacement did not restore truthful active report")
	}
}

func TestCompilerRejectionStillAttestsLastGoodHealth(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, _ := setup(t, p)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	b.protectionUnconfirmed = true
	p.Generation = 2
	p.Spec.Exec.Rules[0].Target.PathClass = []string{"unresolved"}
	c.ModifyHandler(ctx, p)
	if c.LastError() == nil || !c.active[bindingKey(binding())].protectionUnconfirmed || w.reports["policy"].Status.Conditions[0].Reason != "ProtectionUnconfirmed" {
		t.Fatal("compiler rejection falsely claimed last-good enforcement")
	}
	b.protectionUnconfirmed = false
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("healthy re-attestation hid desired compile rejection")
	}
	report := w.reports["policy"]
	if c.active[bindingKey(binding())].protectionUnconfirmed || report.Status.Conditions[0].Status != metav1.ConditionFalse || report.Status.Conditions[0].Reason == "ProtectionUnconfirmed" || !strings.Contains(report.Status.Error, "unresolved path class") || len(report.Status.Conditions) != 2 {
		t.Fatal("healthy rollback did not preserve compile error and confirmed old revision")
	}

}

func TestUnchangedReconcileAttestsWithoutReinstalling(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, _, _ := setup(t, p)
	c.SetBindings(ctx, []Binding{binding()})
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	replacements := b.replacements
	attestations := b.attestations
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b.replacements != replacements || b.attestations != attestations+1 {
		t.Fatal("unchanged revision either skipped health attestation or restarted enforcement")
	}
}

func TestFailedWithdrawalMarksRetainedProtectionUnconfirmed(t *testing.T) {
	b := &fakeBackend{plans: map[string]Plan{}, fail: true, protectionUnconfirmed: true}
	c := &Controller{backend: b, active: map[string]installed{}, withdrawals: map[string]installed{}}
	old := installed{binding: binding()}
	key := bindingKey(old.binding)
	c.active[key] = old
	if err := c.withdraw(context.Background(), old); err == nil {
		t.Fatal("expected failed withdrawal")
	}
	if retained, ok := c.active[key]; !ok || !retained.protectionUnconfirmed {
		t.Fatal("retiring owner falsely retained healthy protection")
	}
}

func TestBindingKeyIncludesExactRuntimeIdentity(t *testing.T) {
	original := binding()
	original.Runtime = "containerd"
	original.CgroupPath = "/cgroup/container"
	original.PID = 123
	original.MountNamespace = 456
	for name, change := range map[string]func(*Binding){
		"runtime":         func(b *Binding) { b.Runtime = "cri-o" },
		"container":       func(b *Binding) { b.ContainerID += "-next" },
		"cgroup-path":     func(b *Binding) { b.CgroupPath += "-next" },
		"cgroup-id":       func(b *Binding) { b.CgroupID++ },
		"mount-namespace": func(b *Binding) { b.MountNamespace++ },
		"pid":             func(b *Binding) { b.PID++ },
		"pod-uid":         func(b *Binding) { b.PodUID += "-next" },
	} {
		t.Run(name, func(t *testing.T) {
			next := original
			change(&next)
			if bindingKey(next) == bindingKey(original) {
				t.Fatal("physical identity or PodUID change aliased retained owner")
			}
		})
	}
	metadata := original
	metadata.PodLabels = map[string]string{"new": "label"}
	metadata.NamespaceLabels = map[string]string{"new": "label"}
	if bindingKey(metadata) != bindingKey(original) {
		t.Fatal("mutable selector labels changed runtime ownership")
	}
}

func TestConfigurationFailureFreezesPendingCleanupAndSuppressesProtection(t *testing.T) {
	ctx := context.Background()
	p := policy("policy", "ns")
	c, b, w, client := setup(t, p)
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	// A committed revision still awaiting cleanup must not be resumed during a
	// failed LIST: the backend may carry a pending publication behind Replace.
	b.postCommit = true
	p.Generation++
	p.Spec.Exec.Rules[0].Target.Path = []string{"/bin/new"}
	c.ModifyHandler(ctx, p)
	if c.LastError() == nil || !c.active[bindingKey(binding())].cleanupPending {
		t.Fatal("test requires a committed pending transition")
	}
	replacements, attestations, retries := b.replacements, b.attestations, b.cleanupRetries
	revision := b.plans[bindingKey(binding())].Revision
	client.PrependReactor("list", "sandboxpolicies", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("API unavailable") })
	if err := c.InitialSync(ctx); err == nil {
		t.Fatal("outage hidden")
	}
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("outage unexpectedly cleared")
	}
	if b.replacements != replacements || b.attestations != attestations || b.cleanupRetries != retries || b.withdrawals != 0 || b.plans[bindingKey(binding())].Revision != revision {
		t.Fatal("configuration outage resumed or changed backend ownership")
	}
	current := c.active[bindingKey(binding())]
	if !current.protectionUnconfirmed || !current.cleanupPending || len(w.reports["policy"].Status.Conditions) != 1 || !strings.Contains(w.reports["policy"].Status.Conditions[0].Message, "protection unconfirmed") {
		t.Fatal("configuration outage advertised unattested pending revision")
	}
}

func TestPhysicalIdentityReplacementWaitsForCommittedRemovalCleanup(t *testing.T) {
	ctx := context.Background()
	c, b, w, _ := setup(t, policy("policy", "ns"))
	old := binding()
	old.PID = 100
	if err := c.SetBindings(ctx, []Binding{old}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	replacements := b.replacements
	next := old
	next.PID++
	b.withdrawPostCommit = true
	if err := c.SetBindings(ctx, []Binding{next}); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if len(c.active) != 0 || len(c.withdrawals) != 1 || b.replacements != replacements || len(w.reports["policy"].Status.Conditions) != 1 {
		t.Fatal("replacement overtook previous physical identity cleanup")
	}
	if err := c.Reconcile(ctx); err == nil || b.replacements != replacements {
		t.Fatal("retry admitted replacement before cleanup", err)
	}
	b.withdrawPostCommit = false
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.withdrawals) != 0 || len(c.active) != 1 || b.replacements != replacements+1 {
		t.Fatal("replacement failed after cleanup completed")
	}
	if _, ok := c.active[bindingKey(next)]; !ok {
		t.Fatal("replacement installed under stale physical identity")
	}
	if err := c.withdraw(ctx, installed{binding: old}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.active[bindingKey(next)]; !ok {
		t.Fatal("stale controller withdrawal removed replacement")
	}
}

// Embedding the narrow interface deliberately hides optional attestation.
type backendWithoutAttestation struct{ Backend }

func TestBindingFailureWithoutReadOnlyAttestationSuppressesProtection(t *testing.T) {
	ctx := context.Background()
	c, b, w, _ := setup(t, policy("policy", "ns"))
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	c.backend = backendWithoutAttestation{b}
	replacements, attestations := b.replacements, b.attestations
	if err := c.ReportBindingFailure(ctx, errors.New("discovery unavailable")); err == nil {
		t.Fatal("outage hidden")
	}
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("outage cleared")
	}
	if b.replacements != replacements || b.attestations != attestations || b.withdrawals != 0 || len(c.active) != 1 {
		t.Fatal("missing attestation changed retained ownership")
	}
	if !c.active[bindingKey(binding())].protectionUnconfirmed || len(w.reports["policy"].Status.Conditions) != 1 {
		t.Fatal("unsupported attestation advertised protection")
	}
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if c.active[bindingKey(binding())].protectionUnconfirmed || len(w.reports["policy"].Status.Conditions) != 2 {
		t.Fatal("authoritative reconciliation failed to restore protection")
	}
}
