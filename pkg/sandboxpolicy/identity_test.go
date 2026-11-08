package sandboxpolicy

import (
	"context"
	"reflect"
	"strings"
	"testing"

	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const saToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func strPtr(s string) *string { return &s }

func identityRule(name string, action api.Action, target api.IdentityTarget) api.IdentityRule {
	return api.IdentityRule{Rule: api.Rule{Name: name, Action: action}, Target: target}
}

// crdIdentityExample is the identity section of sandbox-policy-crd.md
// section 5.5.
func crdIdentityExample() api.PolicySpec {
	yes := true
	harvest := identityRule("no-credential-harvesting", api.ActionDeny, api.IdentityTarget{PathClass: []string{"credentialStore", "sshKeys", "cloudConfig"}})
	harvest.Mode, harvest.Origin = api.RuleEnforce, strPtr("catalog/B1")
	provisioned := identityRule("provisioned-identity-only", api.ActionAllow, api.IdentityTarget{Path: []string{saToken}})
	provisioned.Origin = strPtr("catalog/B3")
	imds := identityRule("no-imds", api.ActionDeny, api.IdentityTarget{IMDS: &yes})
	imds.Mode, imds.Origin = api.RuleEnforce, strPtr("catalog/B2")
	environ := identityRule("no-environ-scrape", api.ActionDeny, api.IdentityTarget{EnvRead: &yes})
	environ.Origin = strPtr("catalog/B1")
	return api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeAudit,
		Identity: &api.IdentitySection{Default: api.ActionAllow, Rules: []api.IdentityRule{harvest, provisioned, imds, environ}}}
}

func expand(t *testing.T, spec api.PolicySpec) (api.PolicySpec, identityReport) {
	t.Helper()
	if err := api.ValidatePolicySpec(spec); err != nil {
		t.Fatal(err)
	}
	out, report, err := expandIdentity(spec)
	if err != nil {
		t.Fatal(err)
	}
	if out.Identity != nil {
		t.Fatal("identity section kept")
	}
	return out, report
}

// readDenied is the gadget's decision for one rule and one read: a path of
// the rule matches and no except does.
func readDenied(t *testing.T, r *filepolicy.Rule, path string) bool {
	t.Helper()
	match := func(globs []string) bool {
		for _, g := range globs {
			p, err := filepolicy.ParsePattern(g)
			if err != nil {
				t.Fatal(err)
			}
			if p.MatchPath(path) {
				return true
			}
		}
		return false
	}
	return match(r.Paths) && !match(r.Except)
}

func TestExpandIdentityCRDExample(t *testing.T) {
	spec := crdIdentityExample()
	out, report := expand(t, spec)
	if len(report.Degraded) != 0 || len(report.Notes) != 0 {
		t.Fatalf("report %+v", report)
	}
	if out.File == nil || out.File.Default != api.ActionAllow || out.Network == nil || out.Network.Default.Egress != api.ActionAllow || out.Network.Default.Listen != api.ActionAllow {
		t.Fatalf("neutral sections: %+v %+v", out.File, out.Network)
	}
	plan, err := TranslateFile(out, nil, FileNode{}, report.OtherProcess)
	if err != nil {
		t.Fatal(err)
	}
	environ := fileRuleByName(plan, "no-environ-scrape")
	if environ == nil || environ.Action != "deny" || environ.Mode != "" || environ.Origin != "catalog/B1" || !environ.OtherProcess ||
		!reflect.DeepEqual(environ.Access, []string{"read"}) || !readDenied(t, environ, "/proc/42/environ") || !readDenied(t, environ, "/proc/42/task/43/environ") ||
		!readDenied(t, environ, "/host/proc/42/environ") {
		t.Fatalf("envRead rule %+v", environ)
	}
	harvest := fileRuleByName(plan, "no-credential-harvesting")
	if harvest == nil || harvest.Action != "deny" || harvest.Mode != "enforce" || harvest.Origin != "catalog/B1" || !reflect.DeepEqual(harvest.Access, []string{"read"}) {
		t.Fatalf("deny rule %+v", harvest)
	}
	allow := fileRuleByName(plan, "provisioned-identity-only")
	if allow == nil || allow.Action != "allow" || allow.Mode != "" || allow.Origin != "catalog/B3" || !reflect.DeepEqual(allow.Access, []string{"read"}) {
		t.Fatalf("allow rule %+v", allow)
	}
	// Every name the kernel can show for the token is lifted from the
	// deny; the other members of the classes stay denied.
	for _, path := range []string{saToken, "/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/..2026_11_05_10_00_00.123456789/token",
		"/run/secrets/kubernetes.io/serviceaccount/..2026_11_05_10_00_00.123456789/token"} {
		if readDenied(t, harvest, path) {
			t.Errorf("provisioned %s is denied", path)
		}
		if p := (filepolicy.Rule{Paths: allow.Paths}); !readDenied(t, &p, path) {
			t.Errorf("allow rule does not cover %s", path)
		}
	}
	for _, path := range []string{"/root/.aws/credentials", "/home/dev/.ssh/id_ed25519", "/root/.aws/config", "/app/.env",
		"/var/run/secrets/kubernetes.io/serviceaccount/namespace"} {
		if path == "/var/run/secrets/kubernetes.io/serviceaccount/namespace" {
			if readDenied(t, harvest, path) {
				t.Errorf("%s is not in a class but is denied", path)
			}
			continue
		}
		if !readDenied(t, harvest, path) {
			t.Errorf("%s is not denied", path)
		}
	}

	net, err := TranslateNetwork(out, DestClasses{})
	if err != nil {
		t.Fatal(err)
	}
	rules := net.Egress.Policy.Egress.Rules
	if len(rules) != 1 || rules[0].Name != "no-imds" || rules[0].Action != "deny" || rules[0].Mode != "enforce" || rules[0].Origin != "catalog/B2" ||
		!reflect.DeepEqual(rules[0].CIDRs, []string{"169.254.169.254/32", "fd00:ec2::254/128"}) {
		t.Fatalf("imds rule %+v", rules)
	}
	if net.Egress.Policy.Egress.Default != "allow" {
		t.Fatalf("egress default %q", net.Egress.Policy.Egress.Default)
	}

	// The input is not changed.
	if spec.Identity == nil || spec.File != nil || spec.Network != nil {
		t.Fatal("expandIdentity mutated its input")
	}
}

func TestExpandIdentityMergesIntoOwnSections(t *testing.T) {
	spec := crdIdentityExample()
	spec.Identity.Rules = spec.Identity.Rules[:3]
	spec.File = &api.FileSection{DefaultByAccess: writesConfined(), Rules: []api.FileRule{fileRule("workspace", api.ActionAllow, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/workspace/**"}}})}}
	spec.File.DefaultByAccess.Read = api.ActionDeny
	spec.Network = &api.NetworkSection{Default: api.NetworkDefault{Egress: api.ActionDeny, Listen: api.ActionDeny},
		Rules: []api.NetworkRule{{Rule: api.Rule{Name: "https", Action: api.ActionAllow}, Target: api.NetworkTarget{CIDR: []string{"0.0.0.0/0"}}}}}
	before := digest(spec)
	out, report := expand(t, spec)
	notes := report.Notes
	if digest(spec) != before {
		t.Fatal("expandIdentity mutated its input")
	}
	if len(notes) != 0 {
		t.Fatalf("notes %q", notes)
	}
	if out.File.DefaultByAccess.Read != api.ActionDeny || len(out.File.Rules) != 3 || out.File.Rules[0].Name != "workspace" {
		t.Fatalf("file section %+v", out.File)
	}
	if out.Network.Default.Egress != api.ActionDeny || len(out.Network.Rules) != 2 || out.Network.Rules[0].Name != "https" {
		t.Fatalf("network section %+v", out.Network)
	}
	plan := translateFile(t, out, nil)
	if fileRuleByName(plan, "provisioned-identity-only") == nil || plan.Doc.Policy.File.Defaults["read"].Action != "deny" {
		t.Fatal("identity allow is not a read allow under the read default deny")
	}
}

func TestExpandIdentityExplicitDenyPathsAreNotSubtracted(t *testing.T) {
	deny := identityRule("creds", api.ActionDeny, api.IdentityTarget{Path: []string{"/root/.aws/**"}, PathClass: []string{"sshKeys"}})
	allow := identityRule("aws", api.ActionAllow, api.IdentityTarget{Path: []string{"/root/.aws/credentials", "/root/.ssh/id_deploy"}})
	taken := fileRule("creds/path", api.ActionDeny, api.FileTarget{PathTarget: api.PathTarget{Path: []string{"/x"}}})
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce, File: &api.FileSection{Default: api.ActionAllow, Rules: []api.FileRule{taken}},
		Identity: &api.IdentitySection{Default: api.ActionAllow, Rules: []api.IdentityRule{deny, allow}}}
	out, _ := expand(t, spec)
	plan := translateFile(t, out, nil)
	classes, explicit := fileRuleByName(plan, "creds"), fileRuleByName(plan, "creds/path~1")
	if classes == nil || explicit == nil || len(explicit.Except) != 0 {
		t.Fatalf("split rules %+v %+v", classes, explicit)
	}
	if readDenied(t, classes, "/root/.ssh/id_deploy") || !readDenied(t, classes, "/root/.ssh/id_rsa") {
		t.Error("class part: the provisioned key is not lifted, or another key is")
	}
	if !readDenied(t, explicit, "/root/.aws/credentials") {
		t.Error("explicit deny path is lifted by an allow")
	}
}

func TestExpandIdentityUnresolvedAndNotExpressible(t *testing.T) {
	no := false
	yes := true
	deny := identityRule("creds", api.ActionDeny, api.IdentityTarget{PathClass: []string{"credentialStore"}})
	deny.Except = []api.IdentityException{{Target: &api.IdentityTarget{IMDS: &yes}}, {Target: &api.IdentityTarget{Path: []string{"/app/.env"}}}}
	allow := identityRule("vault", api.ActionAllow, api.IdentityTarget{PathClass: []string{"vaultAgent"}})
	imdsOff := identityRule("imds-off", api.ActionDeny, api.IdentityTarget{IMDS: &no})
	imds := identityRule("imds", api.ActionDeny, api.IdentityTarget{IMDS: &yes})
	imds.Except = []api.IdentityException{{Target: &api.IdentityTarget{IMDS: &no}}}
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		Identity: &api.IdentitySection{Default: api.ActionDeny, Rules: []api.IdentityRule{deny, allow, imdsOff, imds}}}
	out, report := expand(t, spec)
	if !reflect.DeepEqual(report.Degraded, []api.DegradedRule{{Rule: "default/identity", Requested: api.RuleEnforce, Effective: "audit", Reason: "not-enforceable"}}) {
		t.Fatalf("degraded %+v", report.Degraded)
	}
	got := strings.Join(report.Notes, ";")
	for _, want := range []string{"default deny", "rule creds: except 0 is disabled", "rule imds-off: imds false selects nothing", "rule imds: except 0 is disabled"} {
		if !strings.Contains(got, want) {
			t.Errorf("notes %q lack %q", got, want)
		}
	}
	if r := out.Network.Rules[0]; r.Name != "imds" || len(r.Except) != 0 {
		t.Fatalf("imds rule %+v", r)
	}
	plan := translateFile(t, out, nil)
	// The allow's class is unresolved: its except entry on the deny is
	// disabled (the deny applies there), and the read default runs in audit.
	if plan.Report.NotReady != "ClassUnresolved" || plan.Doc.Policy.File.Defaults["read"].Mode != "audit" {
		t.Fatalf("report %+v defaults %+v", plan.Report, plan.Doc.Policy.File.Defaults)
	}
	if d := fileDegraded(plan, "creds"); d == nil || d.Reason != "except-class-unresolved" {
		t.Fatalf("degraded %+v", plan.Report.Degraded)
	}
	if d := fileDegraded(plan, "vault"); d == nil || d.Reason != "class-unresolved" {
		t.Fatalf("degraded %+v", plan.Report.Degraded)
	}
	creds := fileRuleByName(plan, "creds")
	if readDenied(t, creds, "/app/.env") || !readDenied(t, creds, "/app/.npmrc") {
		t.Fatalf("own except: %+v", creds)
	}
}

func TestExpandIdentityRejects(t *testing.T) {
	yes := true
	actor := identityRule("a", api.ActionDeny, api.IdentityTarget{IMDS: &yes})
	actor.Actor = &api.Actor{Path: []string{"/bin/sh"}}
	mode := identityRule("m", api.ActionDeny, api.IdentityTarget{IMDS: &yes})
	mode.Mode = "strict"
	for name, section := range map[string]api.IdentitySection{
		"actor":   {Default: api.ActionAllow, Rules: []api.IdentityRule{actor}},
		"mode":    {Default: api.ActionAllow, Rules: []api.IdentityRule{mode}},
		"default": {Default: "maybe"},
		"target":  {Default: api.ActionAllow, Rules: []api.IdentityRule{identityRule("t", api.ActionDeny, api.IdentityTarget{})}},
	} {
		t.Run(name, func(t *testing.T) {
			s := section
			if _, _, err := expandIdentity(api.PolicySpec{Identity: &s}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func identityPolicyObject(name string, spec api.PolicySpec) *unstructured.Unstructured {
	p := &api.SandboxPolicy{TypeMeta: metav1.TypeMeta{APIVersion: api.SchemeGroupVersion.String(), Kind: "SandboxPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID("uid-" + name), Generation: 1},
		Spec: api.SandboxPolicySpec{PolicySpec: spec}}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	return &unstructured.Unstructured{Object: raw}
}

func TestIdentityPolicyCompiles(t *testing.T) {
	obj := identityPolicyObject("identity", crdIdentityExample())
	p := parsePolicy(obj)
	if p.err != nil {
		t.Fatal(p.err)
	}
	if p.spec.Identity != nil || p.spec.File == nil || p.spec.Network == nil || len(p.identityStatus.Notes) != 0 || !p.identityStatus.OtherProcess["no-environ-scrape"] {
		t.Fatalf("parsed %+v report %+v", p.spec, p.identityStatus)
	}
	if _, err := Compile(context.Background(), p.identity, p.spec, api.PolicyClasses{}, Binding{}, nil); err != nil {
		t.Fatal(err)
	}
	off := crdIdentityExample()
	off.Mode = api.ModeOff
	if p := parsePolicy(identityPolicyObject("off", off)); p.err != nil || p.spec.File != nil || p.identityStatus.Notes != nil {
		t.Fatalf("off policy expanded: %+v", p)
	}
}

func TestControllerIdentityPlanAndStatus(t *testing.T) {
	ctx := context.Background()
	c, backend, w, _ := setup(t)
	spec := crdIdentityExample()
	spec.Identity.Rules[3].Mode = api.RuleEnforce
	obj := identityPolicyObject("identity", spec)
	c.objects[objectKey(obj)] = obj
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	plan := backend.plans[bindingKey(binding())]
	if len(plan.Policies) != 1 || plan.Policies[0].File == nil || plan.Policies[0].Network == nil ||
		fileRuleByName(plan.Policies[0].File, "no-credential-harvesting") == nil {
		t.Fatalf("identity plan not sent to the backend: %+v", plan)
	}
	if r := fileRuleByName(plan.Policies[0].File, "no-environ-scrape"); r == nil || !r.OtherProcess || r.Mode != "enforce" {
		t.Fatalf("envRead rule %+v", r)
	}
	report := w.reports["uid-identity"]
	for _, cond := range report.Status.Conditions {
		if cond.Type == "IdentityNotEnforced" {
			t.Fatalf("condition %+v", cond)
		}
	}
	if report.Status.Conditions[0].Status != metav1.ConditionTrue || len(report.Status.Degraded) != 0 {
		t.Fatalf("status %+v", report.Status)
	}
}

func TestExpandIdentitySplitKeepsExplicitPathsWithUnresolvedClass(t *testing.T) {
	deny := identityRule("creds", api.ActionDeny, api.IdentityTarget{Path: []string{"/etc/creds"}, PathClass: []string{"emptyClass"}})
	deny.Except = []api.IdentityException{{Target: &api.IdentityTarget{Path: []string{"/etc/creds.pub"}}}}
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		Identity: &api.IdentitySection{Default: api.ActionAllow, Rules: []api.IdentityRule{deny}}}
	out, _ := expand(t, spec)
	plan := translateFile(t, out, nil)
	if fileRuleByName(plan, "creds") != nil {
		t.Fatal("the unresolved class part must keep no path")
	}
	if d := fileDegraded(plan, "creds"); d == nil || d.Reason != "class-unresolved" {
		t.Fatalf("degraded %+v", plan.Report.Degraded)
	}
	explicit := fileRuleByName(plan, "creds/path")
	if explicit == nil || explicit.Mode != "" || !readDenied(t, explicit, "/etc/creds") || readDenied(t, explicit, "/etc/creds.pub") {
		t.Fatalf("explicit part %+v", explicit)
	}
}

func TestExpandIdentitySplitNameFitsTheLimit(t *testing.T) {
	long := strings.Repeat("n", api.MaxRuleNameLength)
	deny := identityRule(long, api.ActionDeny, api.IdentityTarget{Path: []string{"/etc/creds"}, PathClass: []string{"sshKeys"}})
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		Identity: &api.IdentitySection{Default: api.ActionAllow, Rules: []api.IdentityRule{deny}}}
	out, _ := expand(t, spec)
	if err := api.ValidatePolicySpec(out); err != nil {
		t.Fatal(err)
	}
	if name := out.File.Rules[1].Name; len(name) != api.MaxRuleNameLength || !strings.HasSuffix(name, "/path") {
		t.Fatalf("split name %q", name)
	}
}

func TestExpandIdentityEnvRead(t *testing.T) {
	yes := true
	deny := identityRule("env", api.ActionDeny, api.IdentityTarget{EnvRead: &yes})
	deny.Mode = api.RuleEnforce
	lifted := identityRule("env-lifted", api.ActionDeny, api.IdentityTarget{EnvRead: &yes})
	lifted.Except = []api.IdentityException{{Target: &api.IdentityTarget{EnvRead: &yes}}}
	allow := identityRule("env-allow", api.ActionAllow, api.IdentityTarget{EnvRead: &yes})
	spec := api.PolicySpec{Containers: []string{"*"}, Mode: api.ModeEnforce,
		File:     &api.FileSection{DefaultByAccess: writesConfined()},
		Identity: &api.IdentitySection{Default: api.ActionAllow, Rules: []api.IdentityRule{deny, lifted, allow}}}
	out, report := expand(t, spec)
	if len(report.Degraded) != 0 || len(report.Notes) != 0 || len(report.OtherProcess) != 3 {
		t.Fatalf("report %+v", report)
	}
	plan, err := TranslateFile(out, nil, FileNode{}, report.OtherProcess)
	if err != nil {
		t.Fatal(err)
	}
	if r := fileRuleByName(plan, "env"); r == nil || !r.OtherProcess || r.Mode != "enforce" || !readDenied(t, r, "/proc/1/environ") {
		t.Fatalf("deny %+v", r)
	}
	// An envRead except lifts every environ file.
	if r := fileRuleByName(plan, "env-lifted"); r == nil || readDenied(t, r, "/proc/1/environ") || readDenied(t, r, "/proc/1/task/2/environ") {
		t.Fatalf("lifted %+v", r)
	}
	if r := fileRuleByName(plan, "env-allow"); r == nil || r.Action != "allow" || !r.OtherProcess {
		t.Fatalf("allow %+v", r)
	}
	// The flag stays on the envRead rules only.
	for _, r := range plan.Doc.Policy.File.Rules {
		if r.OtherProcess != report.OtherProcess[r.Name] {
			t.Errorf("rule %s otherProcess %v", r.Name, r.OtherProcess)
		}
	}
}
