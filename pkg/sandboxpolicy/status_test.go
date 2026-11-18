package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestStatusIdentityBoundsAndUnprotected(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	r := c.report(p, errors.New(strings.Repeat("x", api.MaxStatusErrorLength+1)))
	if r.Name != api.NodeStatusName("policy", "node-uid") || r.Spec.PolicyRef.UID != "policy" || r.Spec.NodeRef.UID != "node-uid" || len(r.OwnerReferences) != 1 || r.OwnerReferences[0].UID != "policy" {
		t.Fatalf("identity/ownership: %+v", r)
	}
	if !r.Status.Truncated || len(r.Status.Error) != api.MaxStatusErrorLength || r.Status.Conditions[0].Status != metav1.ConditionFalse || !strings.Contains(r.Status.Conditions[0].Message, "no last-good") {
		t.Fatalf("incorrect failure: %+v", r.Status)
	}
}

func parseTypedPolicy(t *testing.T, p *api.SandboxPolicy) desiredPolicy {
	t.Helper()
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	return parsePolicy(&unstructured.Unstructured{Object: raw})
}

func TestDynamicStatusWriterCreateHeartbeatAndIdentity(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	writer := DynamicStatusWriter{Client: client}
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var first api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &first); err != nil {
		t.Fatal(err)
	}
	r.Status.Conditions[0].LastTransitionTime = metav1.Now()
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err = client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var second api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &second); err != nil {
		t.Fatal(err)
	}
	if !first.Status.Conditions[0].LastTransitionTime.Equal(&second.Status.Conditions[0].LastTransitionTime) {
		t.Fatal("heartbeat changed transition timestamp")
	}
	r.Spec.NodeRef.UID = "other"
	if err := writer.WriteStatus(ctx, r); err == nil {
		t.Fatal("accepted different report identity")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" && action.GetSubresource() != "status" {
			t.Fatal("updated spec/parent instead of status")
		}
	}
}

// conditionReasonSyntax is the API server's metav1.Condition reason syntax.
var conditionReasonSyntax = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`)

func TestBoundConditionReason(t *testing.T) {
	long := strings.Repeat("A", 60)
	for _, tc := range []struct {
		name, in, want string
		cut            bool
	}{
		{"single", "Reconciled", "Reconciled", false},
		{"list", "FailClosedRecent,WitnessUnknown", "FailClosedRecent,WitnessUnknown", false},
		{"leading empty item", ",VerdictEventLoss", "VerdictEventLoss", true},
		{"empty items", "A,,B,", "A,B", true},
		{"empty", "", "Unknown", true},
		{"malformed items", "Good,bad-item,1st,Also_Good", "Good,Also_Good", true},
		{"exactly at the bound", strings.Repeat("B", api.MaxStatusConditionKeyLength), strings.Repeat("B", api.MaxStatusConditionKeyLength), false},
		{"over the bound", strings.Repeat("B", api.MaxStatusConditionKeyLength+1), "Unknown", true},
		{"long first item and more", strings.Repeat("B", 127) + ",C", "More", true},
		{"fits", long + "," + long, long + "," + long, false},
		{"whole items dropped", long + "," + long + "," + long, long + "," + long + ",More", true},
		{"first item fits", strings.Repeat("C", 125) + ",D", strings.Repeat("C", 125) + ",D", false},
		{"first item and More", strings.Repeat("C", 120) + ",DDDDDDDDDD", strings.Repeat("C", 120) + ",More", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, cut := BoundConditionReason(tc.in)
			if got != tc.want || cut != tc.cut {
				t.Fatalf("got %q cut %v, want %q %v", got, cut, tc.want, tc.cut)
			}
			if len(got) > api.MaxStatusConditionKeyLength || !conditionReasonSyntax.MatchString(got) {
				t.Fatalf("out of schema: %q", got)
			}
		})
	}
	// Many reasons: whole items only, then More.
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf("Reason%02d", i))
	}
	got, cut := BoundConditionReason(strings.Join(many, ","))
	if !cut || len(got) > api.MaxStatusConditionKeyLength || !strings.HasSuffix(got, ",More") || !conditionReasonSyntax.MatchString(got) {
		t.Fatalf("many reasons %q", got)
	}
	for item := range strings.SplitSeq(strings.TrimSuffix(got, ",More"), ",") {
		if !slices.Contains(many, item) {
			t.Fatalf("cut item %q", item)
		}
	}
}

// The writer fits every condition into the schema and marks the status
// truncated.
func TestDynamicStatusWriterBoundsConditions(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	r.Status.Conditions = append(r.Status.Conditions, metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: strings.Repeat("Reason,", 40) + ",", Message: strings.Repeat("m", 3000)})
	if err := (DynamicStatusWriter{Client: client}).WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var stored api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Status.Truncated {
		t.Fatal("truncation not reported")
	}
	for _, condition := range stored.Status.Conditions {
		if len(condition.Reason) > api.MaxStatusConditionKeyLength || !conditionReasonSyntax.MatchString(condition.Reason) || utf8.RuneCountInString(condition.Message) > api.MaxStatusDiagnosticLength {
			t.Fatalf("out of schema: %+v", condition)
		}
	}
	if r.Status.Conditions[len(r.Status.Conditions)-1].Message != strings.Repeat("m", 3000) {
		t.Fatal("caller's report mutated")
	}
}

func TestStatusAppliedGeneration(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	bind := func(key string, generation int64, unconfirmed bool) {
		identity := p.identity
		identity.Generation = generation
		c.active[key] = installed{plan: Plan{Policies: []CompiledPolicy{{Identity: identity, Revision: fmt.Sprintf("r%d", generation)}}}, protectionUnconfirmed: unconfirmed}
	}
	other := p.identity
	other.UID, other.Generation = "other", 1

	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("no bindings: appliedGeneration %d, want absent", got)
	}
	c.active["other"] = installed{plan: Plan{Policies: []CompiledPolicy{{Identity: other, Revision: "o1"}}}}
	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("other policy's binding counted: appliedGeneration %d", got)
	}
	bind("a", 3, false)
	if got := c.report(p, nil).Status.AppliedGeneration; got != 3 {
		t.Fatalf("current binding: appliedGeneration %d, want 3", got)
	}
	bind("b", 2, false)
	if got := c.report(p, errors.New("rejected")).Status.AppliedGeneration; got != 2 {
		t.Fatalf("mixed bindings: appliedGeneration %d, want the oldest (2)", got)
	}
	bind("c", 1, true)
	if got := c.report(p, nil).Status.AppliedGeneration; got != 2 {
		t.Fatalf("unconfirmed binding counted: appliedGeneration %d, want 2", got)
	}
	delete(c.active, "a")
	delete(c.active, "b")
	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("only unconfirmed bindings: appliedGeneration %d, want absent", got)
	}
	delete(c.active, "c")
	bind("d", 4, false)
	if r := c.report(p, nil); r.Status.AppliedGeneration != 0 || r.Status.ObservedGeneration != 3 {
		t.Fatalf("installed generation above observed must be omitted (admission rejects it): %+v", r.Status)
	}
}

// The CRD admits appliedGeneration only if it is absent or at most
// observedGeneration; zero must reach the API server as an absent field, and a
// heartbeat must remove a previously stored value.
func TestDynamicStatusWriterOmitsZeroAppliedGeneration(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	writer := DynamicStatusWriter{Client: client}
	stored := func() map[string]any {
		t.Helper()
		current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		status, _, _ := unstructured.NestedMap(current.Object, "status")
		return status
	}
	r.Status.AppliedGeneration = 1
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, ok := stored()["appliedGeneration"]; !ok || got != int64(1) {
		t.Fatalf("appliedGeneration not stored: %v", got)
	}
	r.Status.AppliedGeneration = 0
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, ok := stored()["appliedGeneration"]; ok {
		t.Fatalf("zero appliedGeneration stored as %v, want absent", got)
	}
}
