package integration

import (
	"context"
	"reflect"
	"strings"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	profiles "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func completedProfile() *profiles.ContainerProfile {
	return &profiles.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile", Namespace: "ns", UID: "profile-uid", Annotations: map[string]string{helpersv1.StatusMetadataKey: helpersv1.Completed, helpersv1.CompletionMetadataKey: helpersv1.Full}, Labels: map[string]string{helpersv1.ContainerNameMetadataKey: "app"}}, Spec: profiles.ContainerProfileSpec{Execs: []profiles.ExecCalls{{Path: "/bin/z"}, {Path: "/bin/a"}, {Path: "/bin/z"}}}}
}
func TestProfileResolverReadsCompleteLiteralExecsOnly(t *testing.T) {
	p := completedProfile()
	original := p.DeepCopy()
	client := fake.NewSimpleClientset(p)
	resolver := NewProfileResolver(client.SpdxV1beta1())
	rules, err := resolver.ResolveExecs(context.Background(), "ns", "profile", "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Target.Path[0] != "/bin/a" || rules[1].Target.Path[0] != "/bin/z" {
		t.Fatalf("nondeterministic import: %+v", rules)
	}
	for _, r := range rules {
		if r.Action != api.ActionAllow || r.Origin != "ContainerProfile/ns/profile" || r.Target.Argv != nil || r.Name == "" {
			t.Fatalf("wrong import: %+v", r)
		}
	}
	if !reflect.DeepEqual(original, p) {
		t.Fatal("profile mutated")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" || action.GetNamespace() != "ns" {
			t.Fatal("resolver wrote or escaped selected namespace")
		}
	}
}
func TestProfileResolverRejectsUnfaithfulTranslations(t *testing.T) {
	cases := map[string]func(*profiles.ContainerProfile){
		"incomplete":        func(p *profiles.ContainerProfile) { p.Annotations[helpersv1.StatusMetadataKey] = "learning" },
		"partial":           func(p *profiles.ContainerProfile) { p.Annotations[helpersv1.CompletionMetadataKey] = helpersv1.Partial },
		"missing signal":    func(p *profiles.ContainerProfile) { p.Annotations = nil },
		"wrong container":   func(p *profiles.ContainerProfile) { p.Labels[helpersv1.ContainerNameMetadataKey] = "other" },
		"unknown container": func(p *profiles.ContainerProfile) { p.Labels = nil },
		"exact argv":        func(p *profiles.ContainerProfile) { p.Spec.Execs[0].ArgsRequired = true },
		"recorded argv":     func(p *profiles.ContainerProfile) { p.Spec.Execs[0].Args = []string{"-c", "id"} },
		"environment":       func(p *profiles.ContainerProfile) { p.Spec.Execs[0].Envs = []string{"MODE=secret"} },
		"dynamic path":      func(p *profiles.ContainerProfile) { p.Spec.Execs[0].Path = "/tmp/⋯/bin" },
		"glob path":         func(p *profiles.ContainerProfile) { p.Spec.Execs[0].Path = "/bin/*" },
		"relative path":     func(p *profiles.ContainerProfile) { p.Spec.Execs[0].Path = "bin/tool" },
		"missing UID":       func(p *profiles.ContainerProfile) { p.UID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := completedProfile()
			mutate(p)
			resolver := NewProfileResolver(fake.NewSimpleClientset(p).SpdxV1beta1())
			if rules, err := resolver.ResolveExecs(context.Background(), "ns", "profile", "app"); err == nil || rules != nil {
				t.Fatalf("silently widened unsupported import: %+v / %v", rules, err)
			}
		})
	}
}
func TestProfileResolverMultiContainerProjectionAndAmbiguity(t *testing.T) {
	p := completedProfile()
	p.Spec.Execs = nil
	p.Labels = nil
	p.Spec.InitContainers = []profiles.ContainerProfileContainer{{Name: "init", Execs: []profiles.ExecCalls{{Path: "/bin/init"}}}}
	p.Spec.Containers = []profiles.ContainerProfileContainer{{Name: "app", Execs: []profiles.ExecCalls{{Path: "/bin/app"}}}}
	p.Spec.EphemeralContainers = []profiles.ContainerProfileContainer{{Name: "debug", Execs: []profiles.ExecCalls{{Path: "/bin/debug"}}}}
	for _, name := range []string{"app", "init", "debug"} {
		rules, err := NewProfileResolver(fake.NewSimpleClientset(p).SpdxV1beta1()).ResolveExecs(context.Background(), "ns", "profile", name)
		if err != nil || len(rules) != 1 || rules[0].Target.Path[0] != "/bin/"+name {
			t.Fatalf("container projection %s: %+v %v", name, rules, err)
		}
	}
	p.Spec.InitContainers = append(p.Spec.InitContainers, profiles.ContainerProfileContainer{Name: "app"})
	if _, err := NewProfileResolver(fake.NewSimpleClientset(p).SpdxV1beta1()).ResolveExecs(context.Background(), "ns", "profile", "app"); err == nil {
		t.Fatal("ambiguous container name accepted")
	}
	p = completedProfile()
	p.Spec.Containers = []profiles.ContainerProfileContainer{{Name: "app"}}
	if _, err := NewProfileResolver(fake.NewSimpleClientset(p).SpdxV1beta1()).ResolveExecs(context.Background(), "ns", "profile", "app"); err == nil {
		t.Fatal("mixed flat/named execs accepted")
	}
}
func TestProfileResolverEmptyAndMissingSource(t *testing.T) {
	p := completedProfile()
	p.Spec.Execs = nil
	resolver := NewProfileResolver(fake.NewSimpleClientset(p).SpdxV1beta1())
	rules, err := resolver.ResolveExecs(context.Background(), "ns", "profile", "app")
	if err != nil || len(rules) != 0 {
		t.Fatal("known complete empty source rejected")
	}
	if _, err := resolver.ResolveExecs(context.Background(), "different", "profile", "app"); err == nil || !strings.Contains(err.Error(), "read ContainerProfile") {
		t.Fatal("missing namespaced source accepted")
	}
	if _, err := NewProfileResolver(nil).ResolveExecs(context.Background(), "ns", "profile", "app"); err == nil {
		t.Fatal("nil client accepted")
	}
}
