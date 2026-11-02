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
	"k8s.io/apimachinery/pkg/types"
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

type pendingContributor struct{}

func (pendingContributor) Contribute(types.UID) ([]string, []metav1.Condition) {
	return []string{"no-mount"}, []metav1.Condition{{Type: "SeccompAppliesOnRestart", Status: metav1.ConditionTrue, Reason: "ContainersNeedRestart", Message: "1 container(s)"}}
}

func TestPrivilegeWithoutSeccompLayerIsNotReady(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = &api.PrivilegeSection{Default: api.ActionAllow}
	r := c.report(parseTypedPolicy(t, pol), nil)
	if r.Status.Conditions[0].Status != metav1.ConditionFalse || r.Status.Conditions[0].Reason != "NotFullyEnforced" {
		t.Fatalf("Ready: %+v", r.Status.Conditions[0])
	}
	found := false
	for _, cond := range r.Status.Conditions {
		found = found || cond.Type == ConditionPrivilegeNotEnforced
	}
	if !found {
		t.Fatalf("missing %s: %+v", ConditionPrivilegeNotEnforced, r.Status.Conditions)
	}
	// an exec-only policy is unaffected
	if r := c.report(parseTypedPolicy(t, policy("exec", "ns")), nil); r.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("exec-only Ready: %+v", r.Status.Conditions[0])
	}
}

func TestContributedPendingRulesMakeReadyFalse(t *testing.T) {
	c, _, _, _ := setup(t)
	c.AddStatusContributor(pendingContributor{})
	pol := policy("policy", "ns")
	pol.Spec.Privilege = &api.PrivilegeSection{Default: api.ActionAllow}
	r := c.report(parseTypedPolicy(t, pol), nil)
	if r.Status.Conditions[0].Reason != "AppliesOnRestart" || r.Status.Counts.AppliesOnRestart != 1 || len(r.Status.AppliesOnRestart) != 1 {
		t.Fatalf("status: %+v", r.Status)
	}
}
