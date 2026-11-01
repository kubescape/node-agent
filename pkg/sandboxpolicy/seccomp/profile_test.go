package seccomp

import (
	"reflect"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func errno(v uint) *uint { return &v }

func entriesFor(p *specs.LinuxSeccomp, name string) []specs.LinuxSyscall {
	var out []specs.LinuxSyscall
	for _, s := range p.Syscalls {
		if contains(s.Names, name) {
			out = append(out, s)
		}
	}
	return out
}

func TestBuildUnconfined(t *testing.T) {
	rules := []Rule{
		{Name: "no-mount", Mode: api.RuleEnforce, Syscalls: []string{"mount"}},
		{Name: "no-userns", Mode: api.RuleEnforce, Syscalls: []string{"unshare", "clone"}, Flags: cloneNewUser},
		{Name: "watch-ptrace", Mode: api.RuleAudit, Syscalls: []string{"ptrace"}},
		// another policy repeats the denial in audit mode: enforce wins
		{Name: "other", Mode: api.RuleAudit, Syscalls: []string{"mount"}},
	}
	profile, notes, err := Build(Input{Base: BaseUnconfined, Arch: "amd64"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("notes: %v", notes)
	}
	if profile.DefaultAction != specs.ActAllow || !reflect.DeepEqual(profile.Architectures, []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}) {
		t.Fatalf("base: %+v %+v", profile.DefaultAction, profile.Architectures)
	}
	if !reflect.DeepEqual(profile.Flags, []specs.LinuxSeccompFlag{FlagLog}) {
		t.Fatalf("flags: %v", profile.Flags)
	}
	if got := entriesFor(profile, "mount"); len(got) != 1 || got[0].Action != specs.ActErrno || *got[0].ErrnoRet != errnoEPERM || len(got[0].Args) != 0 {
		t.Fatalf("mount: %+v", got)
	}
	userns := []specs.LinuxSeccompArg{{Index: 0, Value: cloneNewUser, ValueTwo: cloneNewUser, Op: specs.OpMaskedEqual}}
	for _, name := range []string{"clone", "unshare"} {
		if got := entriesFor(profile, name); len(got) != 1 || got[0].Action != specs.ActErrno || !reflect.DeepEqual(got[0].Args, userns) {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if got := entriesFor(profile, "clone3"); len(got) != 1 || got[0].Action != specs.ActErrno || *got[0].ErrnoRet != errnoENOSYS {
		t.Fatalf("clone3 must fall back to clone with ENOSYS: %+v", got)
	}
	if got := entriesFor(profile, "ptrace"); len(got) != 1 || got[0].Action != specs.ActLog {
		t.Fatalf("ptrace audit: %+v", got)
	}
	again, _, _ := Build(Input{Base: BaseUnconfined, Arch: "amd64"}, rules)
	if !reflect.DeepEqual(profile, again) {
		t.Fatal("build is not deterministic")
	}
}

func TestBuildAuditOnlyHasNoLogFlagAndNoClone3(t *testing.T) {
	profile, notes, err := Build(Input{Base: BaseUnconfined, Arch: "arm64"}, []Rule{{Name: "a", Mode: api.RuleAudit, Syscalls: []string{"clone"}, Flags: cloneNewUser}})
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Flags) != 0 || len(entriesFor(profile, "clone3")) != 0 {
		t.Fatalf("audit-only profile: %+v", profile)
	}
	if len(notes) != 1 || !reflect.DeepEqual(profile.Architectures, []specs.Arch{specs.ArchAARCH64, specs.ArchARM}) {
		t.Fatalf("notes %v arch %v", notes, profile.Architectures)
	}
}

func TestBuildNeverOverlapsActions(t *testing.T) {
	profile, notes, err := Build(Input{Base: BaseUnconfined, Arch: "amd64"}, []Rule{
		{Name: "a", Mode: api.RuleAudit, Syscalls: []string{"unshare"}},
		{Name: "e", Mode: api.RuleEnforce, Syscalls: []string{"unshare"}, Flags: cloneNewUser},
		{Name: "af", Mode: api.RuleAudit, Syscalls: []string{"unshare"}, Flags: cloneNewNet},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := entriesFor(profile, "unshare")
	want := []specs.LinuxSyscall{
		{Names: []string{"unshare"}, Action: specs.ActErrno, ErrnoRet: errno(errnoEPERM), Args: flagArg(cloneNewUser)},
		{Names: []string{"unshare"}, Action: specs.ActLog, Args: []specs.LinuxSeccompArg{{Index: 0, Value: cloneNewUser, ValueTwo: 0, Op: specs.OpMaskedEqual}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unshare\n got %+v\nwant %+v", got, want)
	}
	if len(notes) != 0 {
		// the audited NEWNET flag is covered by the audited "every call" entry
		t.Fatalf("notes: %v", notes)
	}
}

func TestBuildRootBarrierMatchesExecEnforcementShape(t *testing.T) {
	profile, _, err := Build(Input{Base: BaseUnconfined, Arch: "amd64"}, RootBarrierRules(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"chroot", "pivot_root", "setns", "unshare"} {
		if got := entriesFor(profile, name); len(got) != 1 || got[0].Action != specs.ActErrno || *got[0].ErrnoRet != errnoEPERM || len(got[0].Args) != 0 {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	clone := entriesFor(profile, "clone")
	if len(clone) != 2 {
		t.Fatalf("clone needs one entry per namespace bit: %+v", clone)
	}
}

// runtimeDefaultFixture mirrors the shape of containerd's default profile for a
// container without CAP_SYS_ADMIN, and one with it.
func runtimeDefaultFixture(admin bool) *specs.LinuxSeccomp {
	p := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: errno(errnoEPERM), Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		Syscalls: []specs.LinuxSyscall{{Names: []string{"read", "write", "ptrace", "chroot"}, Action: specs.ActAllow}}}
	if admin {
		p.Syscalls = append(p.Syscalls, specs.LinuxSyscall{Names: []string{"clone", "clone3", "mount", "setns", "unshare"}, Action: specs.ActAllow})
		return p
	}
	p.Syscalls = append(p.Syscalls,
		specs.LinuxSyscall{Names: []string{"clone"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 0, Value: allNamespaces, ValueTwo: 0, Op: specs.OpMaskedEqual}}},
		specs.LinuxSyscall{Names: []string{"clone3"}, Action: specs.ActErrno, ErrnoRet: errno(errnoENOSYS)})
	return p
}

func TestBuildOnRuntimeDefaultOnlyAddsDenials(t *testing.T) {
	base := runtimeDefaultFixture(true)
	before := len(base.Syscalls)
	profile, _, err := Build(Input{Base: BaseRuntimeDefault, Arch: "amd64", Default: base}, []Rule{
		{Name: "no-mount", Mode: api.RuleEnforce, Syscalls: []string{"mount"}},
		{Name: "no-userns", Mode: api.RuleEnforce, Syscalls: []string{"clone", "unshare"}, Flags: cloneNewUser},
		{Name: "watch-ptrace", Mode: api.RuleAudit, Syscalls: []string{"ptrace"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Syscalls) != before || contains(base.Syscalls[1].Names, "mount") == false {
		t.Fatal("base profile was mutated")
	}
	if profile.DefaultAction != specs.ActErrno || len(profile.Architectures) != 3 {
		t.Fatalf("base kept: %+v %v", profile.DefaultAction, profile.Architectures)
	}
	if got := entriesFor(profile, "mount"); len(got) != 0 {
		t.Fatalf("mount must fall to the default deny: %+v", got)
	}
	none := []specs.LinuxSeccompArg{{Index: 0, Value: cloneNewUser, ValueTwo: 0, Op: specs.OpMaskedEqual}}
	for _, name := range []string{"clone", "unshare"} {
		got := entriesFor(profile, name)
		if len(got) != 1 || got[0].Action != specs.ActAllow || !reflect.DeepEqual(got[0].Args, none) {
			t.Fatalf("%s must be allowed only without the flag: %+v", name, got)
		}
	}
	if got := entriesFor(profile, "clone3"); len(got) != 1 || got[0].Action != specs.ActErrno || *got[0].ErrnoRet != errnoENOSYS {
		t.Fatalf("clone3: %+v", got)
	}
	if got := entriesFor(profile, "ptrace"); len(got) != 1 || got[0].Action != specs.ActLog {
		t.Fatalf("audited ptrace must be logged, not silently allowed: %+v", got)
	}
	if got := entriesFor(profile, "read"); len(got) != 1 || got[0].Action != specs.ActAllow {
		t.Fatalf("unrelated syscalls keep their entry: %+v", got)
	}
}

func TestBuildOnRuntimeDefaultWithoutAdmin(t *testing.T) {
	profile, _, err := Build(Input{Base: BaseRuntimeDefault, Arch: "amd64", Default: runtimeDefaultFixture(false)}, []Rule{
		{Name: "no-userns", Mode: api.RuleEnforce, Syscalls: []string{"clone"}, Flags: cloneNewUser},
		{Name: "watch-unshare", Mode: api.RuleAudit, Syscalls: []string{"unshare"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// the existing "no namespace bits" condition already covers the flag
	if got := entriesFor(profile, "clone"); len(got) != 1 || got[0].Args[0].Value != allNamespaces {
		t.Fatalf("clone: %+v", got)
	}
	// unshare is already denied by the base; audit must not allow it
	if got := entriesFor(profile, "unshare"); len(got) != 0 {
		t.Fatalf("unshare: %+v", got)
	}
}

func TestBuildRejects(t *testing.T) {
	if _, _, err := Build(Input{Base: BaseUnconfined, Arch: "s390x"}, nil); err == nil {
		t.Fatal("s390x clone flags are in argument 1")
	}
	if _, _, err := Build(Input{Base: BaseRuntimeDefault, Arch: "amd64"}, nil); err == nil {
		t.Fatal("missing runtime default")
	}
	allowAll := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
	if _, _, err := Build(Input{Base: BaseRuntimeDefault, Arch: "amd64", Default: allowAll}, nil); err == nil {
		t.Fatal("a default-allow base is not a runtime default")
	}
}
