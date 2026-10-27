package sandboxpolicy

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

type resolverFunc func(context.Context, string, string, string) ([]api.ExecRule, error)

func (f resolverFunc) ResolveExecs(ctx context.Context, namespace, name, container string) ([]api.ExecRule, error) {
	return f(ctx, namespace, name, container)
}

func execSpec() api.PolicySpec {
	return api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce, Exec: &api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{{Rule: api.Rule{Name: "shell", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/sh"}}}}}}}
}

func TestCompilePreservesVocabularyAndExpandsClasses(t *testing.T) {
	spec := execSpec()
	yes, no := true, false
	rule := &spec.Exec.Rules[0]
	rule.Actor = &api.Actor{Path: []string{"/bin/parent"}, FromImage: &yes, Ancestor: &api.Ancestor{Path: []string{"/bin/root"}, Depth: 3}, Role: []string{"builder"}, UID: []int64{1000}, Container: []string{"app"}}
	rule.Mode = api.RuleAudit
	rule.Origin = "authored"
	rule.Target = api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/direct"}, PathClass: []string{"tools"}, FromImage: &no, FSType: []string{"overlay"}}, Argv: &api.ArgvPredicate{Contains: []string{"--test"}, Prefix: []string{"sh", "-c"}, StdinIsPipe: &yes}, SetRole: "child"}
	spec.RootRole = "root"
	spec.Classes = &api.PolicyClasses{PathClasses: map[string][]string{"tools": {"/bin/local", "/bin/direct"}}}
	before := digest(spec)
	got, err := Compile(context.Background(), PolicyIdentity{UID: "p"}, spec, api.PolicyClasses{PathClasses: map[string][]string{"tools": {"/bin/global"}}}, Binding{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if digest(spec) != before {
		t.Fatal("compiler mutated input")
	}
	actual := got.Exec.Rules[0]
	if !reflect.DeepEqual(actual.Actor, rule.Actor) || !reflect.DeepEqual(actual.Target.Argv, rule.Target.Argv) || actual.Target.SetRole != "child" || actual.Mode != api.RuleAudit || actual.Origin != "authored" || got.RootRole != "root" {
		t.Fatalf("lost predicates: %#v", got)
	}
	if !reflect.DeepEqual(actual.Target.Path, []string{"/bin/direct", "/bin/global", "/bin/local"}) || len(actual.Target.PathClass) != 0 || actual.Target.FromImage == nil || *actual.Target.FromImage || actual.Target.FSType[0] != "overlay" {
		t.Fatalf("bad expansion: %#v", actual.Target)
	}
}

func TestCompileRejectsUnsupportedMissingAndLimits(t *testing.T) {
	cases := map[string]func(*api.PolicySpec){
		"nonexec": func(s *api.PolicySpec) { s.File = &api.FileSection{} },
		"class":   func(s *api.PolicySpec) { s.Exec.Rules[0].Target.PathClass = []string{"missing"} },
		"source section": func(s *api.PolicySpec) {
			s.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "p"}, Include: []string{"opens"}}}
		},
		"source unavailable": func(s *api.PolicySpec) {
			s.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "p"}, Include: []string{"execs"}}}
		},
		"paths": func(s *api.PolicySpec) {
			for i := 0; i <= MaxPathsPerRule; i++ {
				s.Exec.Rules[0].Target.Path = append(s.Exec.Rules[0].Target.Path, fmt.Sprintf("/bin/%d", i))
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := execSpec()
			change(&s)
			if _, err := Compile(context.Background(), PolicyIdentity{}, s, api.PolicyClasses{}, Binding{}, nil); err == nil {
				t.Fatal("accepted unsupported revision")
			}
		})
	}
	s := execSpec()
	s.Exec.Rules[0].Target.Path = nil
	for i := 0; i < MaxPathsPerRule; i++ {
		s.Exec.Rules[0].Target.Path = append(s.Exec.Rules[0].Target.Path, fmt.Sprintf("/bin/%d", i))
	}
	result, err := Compile(context.Background(), PolicyIdentity{}, s, api.PolicyClasses{}, Binding{}, nil)
	if err != nil || len(result.Exec.Rules[0].Target.Path) != MaxPathsPerRule {
		t.Fatalf("boundary: %v", err)
	}
}

func TestCompileImportsReadOnly(t *testing.T) {
	s := execSpec()
	s.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "profile"}, Include: []string{"execs"}}}
	imported := []api.ExecRule{{Rule: api.Rule{Name: "original", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/z", "/a"}}}}}
	before := digest(imported)
	resolver := resolverFunc(func(_ context.Context, namespace, name, container string) ([]api.ExecRule, error) {
		if namespace != "ns" || name != "profile" || container != "app" {
			t.Fatal("wrong source scope")
		}
		return imported, nil
	})
	got, err := Compile(context.Background(), PolicyIdentity{}, s, api.PolicyClasses{}, Binding{Namespace: "ns", ContainerName: "app"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if digest(imported) != before {
		t.Fatal("mutated resolver objects")
	}
	if got.Exec.Rules[1].Name != "source-0-exec-0" || got.Exec.Rules[1].Origin != "ContainerProfile/ns/profile" {
		t.Fatalf("missing provenance: %+v", got.Exec.Rules[1])
	}
}
