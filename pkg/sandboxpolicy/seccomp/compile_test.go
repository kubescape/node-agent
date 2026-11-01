package seccomp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

var testPolicy = sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Namespace: "agents", Name: "p", UID: "uid-1", Generation: 2}

func privilegeSpec(mode api.PolicyMode, def api.Action, rules ...api.PrivilegeRule) api.PolicySpec {
	return api.PolicySpec{Containers: []string{"*"}, Mode: mode, Privilege: &api.PrivilegeSection{Default: def, Rules: rules}}
}

func deny(name string, syscalls []string, flags ...string) api.PrivilegeRule {
	return api.PrivilegeRule{Rule: api.Rule{Name: name, Action: api.ActionDeny, Origin: "catalog/G1"}, Target: api.PrivilegeTarget{Syscall: syscalls, Flags: flags}}
}

func TestCompileExpandsFamiliesAndFlags(t *testing.T) {
	compiled, err := CompilePolicy(testPolicy, privilegeSpec(api.ModeEnforce, api.ActionAllow,
		deny("no-mount", []string{"mount"}),
		deny("no-userns", []string{"unshare", "clone"}, "CLONE_NEWUSER"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", compiled.Unsupported)
	}
	want := []Rule{
		{Policy: testPolicy, Name: "no-mount", Origin: "catalog/G1", Mode: api.RuleEnforce, Syscalls: []string{"fsconfig", "fsmount", "fsopen", "fspick", "mount", "mount_setattr", "move_mount", "open_tree", "open_tree_attr"}},
		{Policy: testPolicy, Name: "no-userns", Origin: "catalog/G1", Mode: api.RuleEnforce, Syscalls: []string{"clone", "unshare"}, Flags: cloneNewUser},
	}
	if !reflect.DeepEqual(compiled.Rules, want) {
		t.Fatalf("rules\n got %+v\nwant %+v", compiled.Rules, want)
	}
}

func TestCompileModes(t *testing.T) {
	audit := deny("a", []string{"ptrace"})
	audit.Mode = api.RuleAudit
	compiled, err := CompilePolicy(testPolicy, privilegeSpec(api.ModeEnforce, api.ActionAllow, audit, deny("e", []string{"bpf"})))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Rules[0].Mode != api.RuleAudit || compiled.Rules[1].Mode != api.RuleEnforce {
		t.Fatalf("modes: %+v", compiled.Rules)
	}
	for _, mode := range []api.PolicyMode{api.ModeOff, ""} {
		off, err := CompilePolicy(testPolicy, privilegeSpec(mode, api.ActionDeny, deny("e", []string{"bpf"})))
		if err != nil || len(off.Rules) != 0 {
			t.Fatalf("mode %q compiled %+v %v", mode, off.Rules, err)
		}
	}
	inherited, _ := CompilePolicy(testPolicy, privilegeSpec(api.ModeAudit, api.ActionAllow, deny("e", []string{"bpf"})))
	if inherited.Rules[0].Mode != api.RuleAudit {
		t.Fatalf("policy audit mode not inherited: %+v", inherited.Rules)
	}
}

func TestCompileReportsWhatSeccompCannotExpress(t *testing.T) {
	actor := deny("actor", []string{"mount"})
	actor.Actor = &api.Actor{Role: []string{"agent"}}
	capability := api.PrivilegeRule{Rule: api.Rule{Name: "cap", Action: api.ActionDeny}, Target: api.PrivilegeTarget{Capability: []string{"SYS_ADMIN"}}}
	mixed := deny("mixed", []string{"mount"})
	mixed.Target.Capability = []string{"SYS_ADMIN"}
	compiled, err := CompilePolicy(testPolicy, privilegeSpec(api.ModeEnforce, api.ActionAllow,
		actor, capability, mixed,
		deny("setns-flags", []string{"setns"}, "CLONE_NEWNS"),
		deny("bare-clone", []string{"clone"}),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Rules) != 0 {
		t.Fatalf("expected no rules, got %+v", compiled.Rules)
	}
	got := map[string]string{}
	for _, u := range compiled.Unsupported {
		got[u.Rule] = u.Reason
	}
	for _, name := range []string{"actor", "cap", "mixed", "setns-flags", "bare-clone"} {
		if got[name] == "" {
			t.Errorf("rule %s not reported: %v", name, got)
		}
	}
}

func TestCompileDefaultDeny(t *testing.T) {
	allow := api.PrivilegeRule{Rule: api.Rule{Name: "ok-ptrace", Action: api.ActionAllow}, Target: api.PrivilegeTarget{Syscall: []string{"ptrace"}}}
	helper := api.PrivilegeRule{Rule: api.Rule{Name: "helper-mount", Action: api.ActionAllow, Actor: &api.Actor{Role: []string{"sandbox-helper"}}}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}
	compiled, err := CompilePolicy(testPolicy, privilegeSpec(api.ModeEnforce, api.ActionDeny, allow, helper))
	if err != nil {
		t.Fatal(err)
	}
	var plain []string
	flagged := map[string]uint64{}
	for _, r := range compiled.Rules {
		if r.Name != DefaultRuleName {
			t.Fatalf("unexpected rule %+v", r)
		}
		if r.Flags != 0 {
			flagged[r.Syscalls[0]] = r.Flags
		} else {
			plain = r.Syscalls
		}
	}
	if flagged["clone"] != allNamespaces || flagged["unshare"] != allNamespaces {
		t.Fatalf("clone/unshare default must deny namespace flags only: %v", flagged)
	}
	joined := " " + strings.Join(plain, " ") + " "
	for _, must := range []string{" bpf ", " setns ", " clone3 ", " setresuid ", " kexec_file_load "} {
		if !strings.Contains(joined, must) {
			t.Errorf("default deny misses%s", must)
		}
	}
	for _, mustNot := range []string{" ptrace ", " mount ", " fsopen ", " clone ", " unshare "} {
		if strings.Contains(joined, mustNot) {
			t.Errorf("default deny must not include%s", mustNot)
		}
	}
	if len(compiled.Unsupported) != 1 || compiled.Unsupported[0].Rule != "helper-mount" {
		t.Fatalf("scoped allow must be reported: %+v", compiled.Unsupported)
	}
}

func TestCompileRejectsInvalid(t *testing.T) {
	for name, spec := range map[string]api.PolicySpec{
		"default": privilegeSpec(api.ModeEnforce, ""),
		"syscall": privilegeSpec(api.ModeEnforce, api.ActionAllow, deny("x", []string{"reboot"})),
		"flag":    privilegeSpec(api.ModeEnforce, api.ActionAllow, deny("x", []string{"unshare"}, "CLONE_NEWTIME")),
	} {
		if _, err := CompilePolicy(testPolicy, spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
