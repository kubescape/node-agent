// Package seccomp compiles the syscall rules of a SandboxPolicy privilege section
// into an OCI seccomp profile. The kernel applies such a profile only when a
// container starts, so a changed profile reaches running containers on restart.
package seccomp

import (
	"fmt"
	"sort"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// Namespace flag bits shared by clone(2) and unshare(2). Hard-coded so the
// compiler also builds and tests on non-Linux hosts.
const (
	cloneNewNS     uint64 = 0x00020000
	cloneNewCgroup uint64 = 0x02000000
	cloneNewUTS    uint64 = 0x04000000
	cloneNewIPC    uint64 = 0x08000000
	cloneNewUser   uint64 = 0x10000000
	cloneNewPID    uint64 = 0x20000000
	cloneNewNet    uint64 = 0x40000000
	allNamespaces         = cloneNewNS | cloneNewCgroup | cloneNewUTS | cloneNewIPC | cloneNewUser | cloneNewPID | cloneNewNet
)

var namespaceFlags = map[string]uint64{
	"CLONE_NEWNS":     cloneNewNS,
	"CLONE_NEWCGROUP": cloneNewCgroup,
	"CLONE_NEWUTS":    cloneNewUTS,
	"CLONE_NEWIPC":    cloneNewIPC,
	"CLONE_NEWUSER":   cloneNewUser,
	"CLONE_NEWPID":    cloneNewPID,
	"CLONE_NEWNET":    cloneNewNet,
}

// syscallFamilies expands a CRD syscall name to every kernel entry point with
// the same effect. Without this, "deny mount" is bypassed by the new mount API
// and "deny setuid" by setresuid or a 32-bit setuid32. Names unknown on an ABI
// are skipped by the runtime.
var syscallFamilies = map[string][]string{
	"unshare":           {"unshare"},
	"setns":             {"setns"},
	"clone":             {"clone"},
	"clone3":            {"clone3"},
	"mount":             {"mount", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "open_tree_attr", "mount_setattr"},
	"umount2":           {"umount2", "umount"},
	"pivot_root":        {"pivot_root"},
	"chroot":            {"chroot"},
	"open_tree":         {"open_tree", "open_tree_attr"},
	"move_mount":        {"move_mount"},
	"ptrace":            {"ptrace"},
	"process_vm_readv":  {"process_vm_readv"},
	"process_vm_writev": {"process_vm_writev"},
	"init_module":       {"init_module"},
	"finit_module":      {"finit_module"},
	"bpf":               {"bpf"},
	"perf_event_open":   {"perf_event_open"},
	"kexec_load":        {"kexec_load", "kexec_file_load"},
	"keyctl":            {"keyctl", "add_key", "request_key"},
	"userfaultfd":       {"userfaultfd"},
	"io_uring_setup":    {"io_uring_setup"},
	"mknod":             {"mknod", "mknodat"},
	"setuid":            {"setuid", "setreuid", "setresuid", "setfsuid", "setuid32", "setreuid32", "setresuid32", "setfsuid32"},
	"setgid":            {"setgid", "setregid", "setresgid", "setfsgid", "setgroups", "setgid32", "setregid32", "setresgid32", "setfsgid32", "setgroups32"},
	"capset":            {"capset"},
}

// flaggable syscalls take namespace flags in argument 0 on x86_64 and arm64.
// setns is excluded: nstype 0 joins any namespace, so a flag match is bypassable.
var flaggable = map[string]bool{"clone": true, "unshare": true}

// Rule is one compiled deny. Flags is a namespace-bit mask; zero means every
// call. Mode is the effective audit or enforce mode.
type Rule struct {
	Policy   sandboxpolicy.PolicyIdentity
	Name     string
	Origin   string
	Mode     api.RuleMode
	Syscalls []string
	Flags    uint64
}

// Unsupported records a rule that seccomp cannot express. It is reported, never
// silently dropped or widened.
type Unsupported struct {
	Policy sandboxpolicy.PolicyIdentity
	Rule   string
	Reason string
}

type Compiled struct {
	Policy      sandboxpolicy.PolicyIdentity
	Rules       []Rule
	Unsupported []Unsupported
}

// DefaultRuleName names the rules produced by a privilege section's default deny.
const DefaultRuleName = "privilege.default"

// CompilePolicy compiles the syscall rules of one policy. Capability, mount
// filesystem and path-class targets belong to other hooks and are reported as
// unsupported here. An inactive policy compiles to nothing.
func CompilePolicy(identity sandboxpolicy.PolicyIdentity, spec api.PolicySpec) (Compiled, error) {
	result := Compiled{Policy: identity}
	if spec.Privilege == nil || (spec.Mode != api.ModeAudit && spec.Mode != api.ModeEnforce) {
		return result, nil
	}
	section := spec.Privilege
	if section.Default != api.ActionAllow && section.Default != api.ActionDeny {
		return result, fmt.Errorf("privilege requires an allow/deny default")
	}
	unsupported := func(rule, reason string) {
		result.Unsupported = append(result.Unsupported, Unsupported{Policy: identity, Rule: rule, Reason: reason})
	}
	// Syscalls with an allow exception that seccomp cannot scope are left to
	// other layers rather than denied for every process in the container.
	allowed := make(map[string]bool)
	scopedAllow := make(map[string]bool)
	for _, r := range section.Rules {
		if r.Action != api.ActionAllow && r.Action != api.ActionDeny {
			return result, fmt.Errorf("rule %q has invalid action", r.Name)
		}
		if r.Mode != "" && r.Mode != api.RuleAudit && r.Mode != api.RuleEnforce {
			return result, fmt.Errorf("rule %q has invalid mode", r.Name)
		}
		if len(r.Target.Syscall) == 0 {
			unsupported(r.Name, "not a syscall target; enforced by another layer")
			continue
		}
		if reason := nonSyscallFields(r.Target); reason != "" {
			unsupported(r.Name, reason)
			continue
		}
		mask, err := flagMask(r.Target.Flags)
		if err != nil {
			return result, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		for _, name := range r.Target.Syscall {
			if _, ok := syscallFamilies[name]; !ok {
				return result, fmt.Errorf("rule %q: unknown syscall %q", r.Name, name)
			}
		}
		if r.Action == api.ActionAllow {
			for _, name := range r.Target.Syscall {
				if r.Actor != nil || mask != 0 {
					scopedAllow[name] = true
				} else {
					allowed[name] = true
				}
			}
			if r.Actor != nil || mask != 0 {
				unsupported(r.Name, "allow with an actor or flags cannot be scoped in seccomp; these syscalls are not denied by seccomp")
			}
			continue
		}
		if r.Actor != nil {
			unsupported(r.Name, "actor predicates cannot be expressed in seccomp")
			continue
		}
		rule := Rule{Policy: identity, Name: r.Name, Origin: r.Origin, Mode: effectiveMode(spec.Mode, r.Mode), Flags: mask}
		for _, name := range r.Target.Syscall {
			if mask != 0 && !flaggable[name] {
				unsupported(r.Name, fmt.Sprintf("flags cannot be matched on %s", name))
				rule.Syscalls = nil
				break
			}
			if name == "clone" && mask == 0 {
				unsupported(r.Name, "clone without flags would deny every process creation")
				rule.Syscalls = nil
				break
			}
			rule.Syscalls = append(rule.Syscalls, syscallFamilies[name]...)
		}
		if len(rule.Syscalls) > 0 {
			rule.Syscalls = sortedUnique(rule.Syscalls)
			result.Rules = append(result.Rules, rule)
		}
	}
	if section.Default == api.ActionDeny {
		mode := effectiveMode(spec.Mode, "")
		// Families overlap (mount contains open_tree and move_mount), so an allow
		// covers every member of its family, whichever key names it.
		covered := make(map[string]bool)
		for name := range allowed {
			for _, member := range syscallFamilies[name] {
				covered[member] = true
			}
		}
		for name := range scopedAllow {
			for _, member := range syscallFamilies[name] {
				covered[member] = true
			}
		}
		var plain []string
		for name, family := range syscallFamilies {
			if flaggable[name] {
				if !covered[name] {
					result.Rules = append(result.Rules, Rule{Policy: identity, Name: DefaultRuleName, Mode: mode, Syscalls: []string{name}, Flags: allNamespaces})
				}
				continue
			}
			for _, member := range family {
				if !covered[member] {
					plain = append(plain, member)
				}
			}
		}
		if len(plain) > 0 {
			result.Rules = append(result.Rules, Rule{Policy: identity, Name: DefaultRuleName, Mode: mode, Syscalls: sortedUnique(plain)})
		}
	}
	sort.SliceStable(result.Rules, func(i, j int) bool { return result.Rules[i].Name < result.Rules[j].Name })
	return result, nil
}

func nonSyscallFields(t api.PrivilegeTarget) string {
	if len(t.Capability) > 0 || len(t.MountFSType) > 0 || len(t.PathClass) > 0 || len(t.Path) > 0 || t.FromImage != nil || len(t.FSType) > 0 {
		return "syscall targets cannot be combined with other primitives in seccomp"
	}
	return ""
}

func flagMask(names []string) (uint64, error) {
	var mask uint64
	for _, name := range names {
		bit, ok := namespaceFlags[name]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", name)
		}
		mask |= bit
	}
	return mask, nil
}

func effectiveMode(policy api.PolicyMode, rule api.RuleMode) api.RuleMode {
	if rule != "" {
		return rule
	}
	if policy == api.ModeEnforce {
		return api.RuleEnforce
	}
	return api.RuleAudit
}

func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
