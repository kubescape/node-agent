package integration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// conditionReasonSyntax is the API server's metav1.Condition reason syntax.
var conditionReasonSyntax = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`)

// Through the real writer chain (readiness, shared health, dynamic writer),
// every reason at once, a 2 KB IG error and 100 binding faults still fit the
// storage schema (reason <= 128, message <= 512, reason syntax) in Ready and
// Degraded: a rejected status update would leave a stale Ready True.
func TestSharedHealthStatusFitsSchema(t *testing.T) {
	ctx := sandboxpolicy.WithPolicyExec(context.Background(), true)
	igError := errors.New(strings.Repeat("ig failure detail ", 2048/18+1))
	var faults []error
	for i := range 100 {
		faults = append(faults, fmt.Errorf("cgroup %d: shared route committed generation %d, compiled for %d", 1000+i, i+2, i+1))
	}
	degraded := errors.Join(
		fmt.Errorf("window: %w", fullruntime.ErrSharedFailClosedDegraded),
		fmt.Errorf("lost: %w", fullruntime.ErrSharedVerdictEventLoss),
		fmt.Errorf("ledger: %w", fullruntime.ErrSharedImageLedger),
		fmt.Errorf("degraded: adoption refused: %w", igError),
	)
	base := igbackend.SharedNodeHealth{
		Started: true, Degraded: degraded, BindingFaults: errors.Join(faults...),
		FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedDegraded},
		FactsErr:   fmt.Errorf("facts: %w", igError), CountersErr: fmt.Errorf("counters: %w", igError),
	}
	notReady := base
	notReady.Ready = fmt.Errorf("%w: %w", fullruntime.ErrSharedNodeNotReady, igError)
	notReady.FailClosedErr = fmt.Errorf("witness: %w", igError)
	qualification := notReady
	qualification.Qualification = true
	sectionDegraded := metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "FailClosedRecent,WitnessUnknown,SettleDeadlinePassed", Message: strings.Repeat("file section degraded ", 40)}
	for name, health := range map[string]igbackend.SharedNodeHealth{
		"product ready":  base,
		"product":        notReady,
		"qualification":  qualification,
		"start failed":   {StartErr: igError},
		"unavailable":    {Unavailable: fmt.Errorf("%w: %w", fullruntime.ErrSharedNativeUnavailable, igError)},
		"node not ready": {Started: true, Ready: fmt.Errorf("%w: %w", fullruntime.ErrSharedNodeNotReady, igError)},
	} {
		t.Run(name, func(t *testing.T) {
			client := fake.NewSimpleDynamicClientWithCustomListKinds(k8sruntime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.NodeStatusGVR: "SandboxPolicyNodeStatusList"})
			var observed, snapshot atomic.Uint64
			chain := readinessWriter{inner: engineStatusWriter(fakeSharedHealthEngine{health: health}, sandboxpolicy.DynamicStatusWriter{Client: client}), observed: &observed, snapshot: &snapshot}
			report := &api.SandboxPolicyNodeStatus{
				TypeMeta:   metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicyNodeStatus"},
				ObjectMeta: metav1.ObjectMeta{Name: "status", Namespace: "ns"},
				Spec:       api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{Kind: "SandboxPolicy", Name: "p", UID: "p"}, NodeRef: api.NodeReference{Name: "n", UID: "n"}},
				Status: &api.NodeStatus{ObservedGeneration: 1, LastReported: metav1.Now(), Conditions: []metav1.Condition{
					{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", LastTransitionTime: metav1.Now()}, sectionDegraded,
				}},
			}
			if err := chain.WriteStatus(ctx, report); err != nil {
				t.Fatal(err)
			}
			current, err := client.Resource(sandboxpolicy.NodeStatusGVR).Namespace("ns").Get(context.Background(), "status", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var stored api.SandboxPolicyNodeStatus
			if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &stored); err != nil {
				t.Fatal(err)
			}
			conditions := map[string]metav1.Condition{}
			for _, c := range stored.Status.Conditions {
				if len(c.Reason) > api.MaxStatusConditionKeyLength || !conditionReasonSyntax.MatchString(c.Reason) || utf8.RuneCountInString(c.Message) > api.MaxStatusDiagnosticLength {
					t.Fatalf("%s out of schema: reason %d %q, message %d", c.Type, len(c.Reason), c.Reason, utf8.RuneCountInString(c.Message))
				}
				conditions[c.Type] = c
			}
			if !stored.Status.Truncated {
				t.Fatal("truncation not reported")
			}
			if conditions["Degraded"].Status != metav1.ConditionTrue || !strings.HasPrefix(conditions["Degraded"].Reason, "FailClosedRecent,WitnessUnknown,SettleDeadlinePassed") {
				t.Fatalf("degraded %+v", conditions["Degraded"])
			}
			// Every Degraded reason at once overflows: whole reasons, then More.
			if strings.HasPrefix(name, "product") && !strings.HasSuffix(conditions["Degraded"].Reason, ",More") {
				t.Fatalf("reason list not cut: %q", conditions["Degraded"].Reason)
			}
			if wantReady := name == "product ready"; (conditions["Ready"].Status == metav1.ConditionTrue) != wantReady {
				t.Fatalf("ready %+v", conditions["Ready"])
			}
		})
	}
}
