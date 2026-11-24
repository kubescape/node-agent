package sandboxpolicy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func loaderExecRule(name string, action api.Action, paths ...string) api.ExecRule {
	return api.ExecRule{Rule: api.Rule{Name: name, Action: action}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: paths}}}
}

// A path names a loader only when its file name starts with a literal "ld-":
// a library glob that matches a loader's file name does not.
func TestLoaderAllowRule(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/usr/lib64/ld-linux-x86-64.so.2", true},
		{"/lib/ld-musl-*", true},
		{"/lib/x86_64-linux-gnu/ld-2.31.so", true},
		{"/opt/app/ld-linux-x86-64.so.2", true},
		{"/usr/lib/**/*.so*", false},
		{"/lib/x86_64-linux-gnu/*.so.*", false},
		{"/opt/app/*.so*", false},
		{"/lib64/*ld-linux-x86-64.so.2", false},
		{"/**", false},
		{"/lib/ld-linux.so.2", false},
	} {
		exec := api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{loaderExecRule("allow", api.ActionAllow, "/usr/bin/env", tc.path)}}
		rule, path, ok := LoaderAllowRule(exec)
		if ok != tc.want || (ok && (rule.Name != "allow" || path != tc.path)) {
			t.Errorf("%s: got %q %q %v, want %v", tc.path, rule.Name, path, ok, tc.want)
		}
	}
	// A deny of a loader path is not an allow.
	if _, _, ok := LoaderAllowRule(api.ExecSection{Rules: []api.ExecRule{loaderExecRule("d", api.ActionDeny, "/lib/ld-musl-*")}}); ok {
		t.Fatal("deny counted as an allow")
	}
}

func TestExecDeniesByPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		exec api.ExecSection
		want bool
	}{
		{"deny default", api.ExecSection{Default: api.ActionDeny}, true},
		{"deny rule with paths", api.ExecSection{Default: api.ActionAllow, Rules: []api.ExecRule{loaderExecRule("d", api.ActionDeny, "/usr/bin/id")}}, true},
		{"deny rule without paths", api.ExecSection{Default: api.ActionAllow, Rules: []api.ExecRule{loaderExecRule("d", api.ActionDeny)}}, false},
		{"allow only", api.ExecSection{Default: api.ActionAllow, Rules: []api.ExecRule{loaderExecRule("a", api.ActionAllow, "/usr/bin/id")}}, false},
	} {
		if got := ExecDeniesByPath(tc.exec); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

// A loader allow that turns the loader deny off is reported in the status,
// with the rule that caused it. The status judges the compiled section, as
// the full compiler does: path classes and ContainerProfile rules count.
func TestControllerReportsLoaderAllow(t *testing.T) {
	classRule := func(name string, action api.Action, class string) api.ExecRule {
		return api.ExecRule{Rule: api.Rule{Name: name, Action: action}, Target: api.ExecTarget{PathTarget: api.PathTarget{PathClass: []string{class}}}}
	}
	classes := &api.PolicyClasses{PathClasses: map[string][]string{"tools": {"/usr/bin/id"}, "loaders": {"/lib/ld-musl-*"}}}
	for _, tc := range []struct {
		name    string
		rules   []api.ExecRule
		def     api.Action
		classes *api.PolicyClasses
		profile []api.ExecRule
		want    []string
	}{
		{name: "loader allowed", rules: []api.ExecRule{loaderExecRule("tools", api.ActionDeny, "/usr/bin/id"), loaderExecRule("ldso", api.ActionAllow, "/lib64/ld-linux-x86-64.so.2")}, def: api.ActionAllow, want: []string{"ldso", "/lib64/ld-linux-x86-64.so.2"}},
		{name: "library glob", rules: []api.ExecRule{loaderExecRule("tools", api.ActionDeny, "/usr/bin/id"), loaderExecRule("libs", api.ActionAllow, "/usr/lib/**/*.so*")}, def: api.ActionDeny},
		{name: "no path deny", rules: []api.ExecRule{loaderExecRule("ldso", api.ActionAllow, "/lib64/ld-linux-x86-64.so.2")}, def: api.ActionAllow},
		{name: "deny and allow through path classes", rules: []api.ExecRule{classRule("tools", api.ActionDeny, "tools"), classRule("musl", api.ActionAllow, "loaders")}, def: api.ActionAllow, classes: classes, want: []string{"musl", "/lib/ld-musl-*"}},
		{name: "loader learned in a ContainerProfile", def: api.ActionDeny, profile: []api.ExecRule{loaderExecRule("learned", api.ActionAllow, "/usr/lib64/ld-linux-x86-64.so.2")}, want: []string{"source-0-exec-0", "origin ContainerProfile/ns/learned", "/usr/lib64/ld-linux-x86-64.so.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, _, w, _ := setup(t)
			spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce, Classes: tc.classes, Exec: &api.ExecSection{Default: tc.def, Rules: tc.rules}}
			if tc.profile != nil {
				spec.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "learned"}, Include: []string{"execs"}}}
				c.resolver = resolverFunc(func(context.Context, string, string, string) ([]api.ExecRule, error) { return tc.profile, nil })
			}
			obj := identityPolicyObject("loader", spec)
			c.objects[objectKey(obj)] = obj
			if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
				t.Fatal(err)
			}
			report := w.reports["uid-loader"]
			if report == nil {
				t.Fatal("no report")
			}
			var got *metav1.Condition
			for i, cond := range report.Status.Conditions {
				if cond.Type == "ExecLoaderAllowed" {
					got = &report.Status.Conditions[i]
				}
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("unexpected condition %+v", got)
				}
				return
			}
			if got == nil || got.Status != metav1.ConditionTrue || got.Reason != "LoaderAllowRule" {
				t.Fatalf("condition %s", fmt.Sprint(got))
			}
			for _, want := range tc.want {
				if !strings.Contains(got.Message, want) {
					t.Fatalf("message %q lacks %q", got.Message, want)
				}
			}
		})
	}
}
