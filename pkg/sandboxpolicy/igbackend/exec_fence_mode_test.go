package igbackend

import (
	rf "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"testing"
)

func TestExecFenceModeCompiledRuleOverrides(t *testing.T) {
	for _, tc := range []struct {
		mode     api.PolicyMode
		override api.RuleMode
		want     rf.Mode
	}{{"audit", "audit", rf.Audit}, {"audit", "enforce", rf.Strict}, {"enforce", "audit", rf.Strict}} {
		p := sandboxpolicy.Plan{Revision: "plan", Policies: []sandboxpolicy.CompiledPolicy{{Identity: sandboxpolicy.PolicyIdentity{UID: "uid"}, Revision: "r", Mode: tc.mode, Exec: api.ExecSection{Rules: []api.ExecRule{{Rule: api.Rule{Name: "rule", Action: "deny", Mode: tc.override}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/false"}}}}}}}}}
		got, err := ExecFenceMode(sandboxpolicy.Binding{ContainerName: "app"}, p)
		if err != nil || got != tc.want {
			t.Fatalf("mode=%s override=%s got=%d err=%v", tc.mode, tc.override, got, err)
		}
	}
}
func TestExecFenceModeRejectsUnresolvedPlan(t *testing.T) {
	p := fullPlan()
	p.Policies[0].Exec.Rules[0].Target.PathClass = []string{"unresolved"}
	if _, err := ExecFenceMode(sandboxpolicy.Binding{ContainerName: "app"}, p); err == nil {
		t.Fatal("unresolved class accepted")
	}
}
