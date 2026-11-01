package seccomp

import (
	"fmt"
	"sort"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	errnoEPERM  uint = 1
	errnoENOSYS uint = 38
	// FlagLog makes the kernel log ERRNO decisions, which is how denials
	// become visible to audit_seccomp.
	FlagLog specs.LinuxSeccompFlag = "SECCOMP_FILTER_FLAG_LOG"
)

// Base is the profile the container would get without SandboxPolicy.
type Base int

const (
	// BaseUnconfined is a pod without a seccomp profile: everything is allowed.
	BaseUnconfined Base = iota
	// BaseRuntimeDefault is the runtime's default-deny allowlist, kept as is so
	// SandboxPolicy only ever adds denials on top of it.
	BaseRuntimeDefault
)

// Input describes one container. Default is the runtime's base profile,
// required for BaseRuntimeDefault.
type Input struct {
	Base    Base
	Arch    string
	Default *specs.LinuxSeccomp
}

// RootBarrierRuleName names the denials that exec enforcement relies on.
const RootBarrierRuleName = "exec-root-barrier"

// RootBarrierRules keep a process from changing its root between two exec
// checks: unconditional denials, plus the namespace bits of clone. They belong
// to the enforced exec policy that needs them.
func RootBarrierRules(policy sandboxpolicy.PolicyIdentity) []Rule {
	return []Rule{
		{Policy: policy, Name: RootBarrierRuleName, Mode: api.RuleEnforce, Syscalls: []string{"chroot", "pivot_root", "setns", "unshare", "clone3"}},
		{Policy: policy, Name: RootBarrierRuleName, Mode: api.RuleEnforce, Syscalls: []string{"clone"}, Flags: cloneNewUser | cloneNewNS},
	}
}

// decision is the strongest verdict requested for one syscall.
type decision struct {
	all   api.RuleMode            // every call
	flags map[uint64]api.RuleMode // single namespace bit -> mode
}

func stronger(a, b api.RuleMode) api.RuleMode {
	if a == api.RuleEnforce || b == api.RuleEnforce {
		return api.RuleEnforce
	}
	if a == api.RuleAudit || b == api.RuleAudit {
		return api.RuleAudit
	}
	return ""
}

// merge folds rules from every policy into one decision per syscall. Deny wins
// across policies and enforce wins over audit.
func merge(rules []Rule) map[string]*decision {
	out := make(map[string]*decision)
	for _, r := range rules {
		for _, name := range r.Syscalls {
			d := out[name]
			if d == nil {
				d = &decision{flags: make(map[uint64]api.RuleMode)}
				out[name] = d
			}
			if r.Flags == 0 {
				d.all = stronger(d.all, r.Mode)
				continue
			}
			for bit := uint64(1); bit != 0 && bit <= r.Flags; bit <<= 1 {
				if r.Flags&bit != 0 {
					d.flags[bit] = stronger(d.flags[bit], r.Mode)
				}
			}
		}
	}
	for _, d := range out {
		// A call already covered for every argument needs no per-flag entry of
		// equal or weaker mode. An enforced flag under an audited call stays,
		// and the audited call is then logged only without those flags.
		for bit, mode := range d.flags {
			if d.all == api.RuleEnforce || (d.all == api.RuleAudit && mode == api.RuleAudit) {
				delete(d.flags, bit)
			}
		}
	}
	return out
}

// Build returns the profile for one container and the notes for anything it
// could not express. The result is deterministic for equal input.
func Build(in Input, rules []Rule) (*specs.LinuxSeccomp, []string, error) {
	if in.Arch != "amd64" && in.Arch != "arm64" {
		return nil, nil, fmt.Errorf("unsupported architecture %q", in.Arch)
	}
	decisions := merge(rules)
	var notes []string
	// An enforced flag and an audited flag on one syscall would need two
	// overlapping entries with different actions for a call that sets both.
	// Keep the enforced one and say so.
	for _, name := range sortedNames(decisions) {
		d := decisions[name]
		if enforcedMask(d.flags) == 0 {
			continue
		}
		for bit, mode := range d.flags {
			if mode == api.RuleAudit {
				delete(d.flags, bit)
				notes = append(notes, fmt.Sprintf("%s: audited flag %#x dropped next to enforced flags", name, bit))
			}
		}
	}
	// clone3 passes its flags in memory, out of seccomp's reach. Answer ENOSYS so
	// glibc falls back to clone(2), where the flag rules apply. EPERM would make
	// glibc fail every new thread instead.
	if d := decisions["clone"]; d != nil && hasEnforcedFlag(d) {
		c3 := decisions["clone3"]
		if c3 == nil {
			c3 = &decision{flags: map[uint64]api.RuleMode{}}
			decisions["clone3"] = c3
		}
		c3.all = api.RuleEnforce
	} else if d != nil && len(d.flags) > 0 {
		notes = append(notes, "clone3 cannot be audited by flags; audit covers clone(2) only")
	}
	var profile *specs.LinuxSeccomp
	var err error
	switch in.Base {
	case BaseUnconfined:
		profile = unconfinedProfile(in.Arch, decisions)
	case BaseRuntimeDefault:
		if in.Default == nil {
			return nil, nil, fmt.Errorf("runtime default profile is required")
		}
		var extra []string
		profile, extra, err = onRuntimeDefault(in.Default, decisions)
		notes = append(notes, extra...)
	default:
		return nil, nil, fmt.Errorf("unknown base %d", in.Base)
	}
	if err != nil {
		return nil, nil, err
	}
	if enforces(decisions) {
		profile.Flags = appendFlag(profile.Flags, FlagLog)
	}
	sort.Strings(notes)
	return profile, notes, nil
}

func hasEnforcedFlag(d *decision) bool {
	if d.all == api.RuleEnforce {
		return true
	}
	for _, mode := range d.flags {
		if mode == api.RuleEnforce {
			return true
		}
	}
	return false
}

func enforces(decisions map[string]*decision) bool {
	for _, d := range decisions {
		if hasEnforcedFlag(d) {
			return true
		}
	}
	return false
}

// architectures lists the native and compat ABIs, as runtime default profiles
// do. Leaving out a compat ABI would make the runtime kill its syscalls even
// under an audit-only policy; the syscall names resolve per ABI.
func architectures(arch string) []specs.Arch {
	if arch == "amd64" {
		return []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	}
	return []specs.Arch{specs.ArchAARCH64, specs.ArchARM}
}

func action(mode api.RuleMode, name string) (specs.LinuxSeccompAction, *uint) {
	if mode != api.RuleEnforce {
		return specs.ActLog, nil
	}
	errno := errnoEPERM
	if name == "clone3" {
		errno = errnoENOSYS
	}
	return specs.ActErrno, &errno
}

func flagArg(bit uint64) []specs.LinuxSeccompArg {
	return []specs.LinuxSeccompArg{{Index: 0, Value: bit, ValueTwo: bit, Op: specs.OpMaskedEqual}}
}

func sortedNames(decisions map[string]*decision) []string {
	names := make([]string, 0, len(decisions))
	for name := range decisions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedBits(flags map[uint64]api.RuleMode) []uint64 {
	bits := make([]uint64, 0, len(flags))
	for bit := range flags {
		bits = append(bits, bit)
	}
	sort.Slice(bits, func(i, j int) bool { return bits[i] < bits[j] })
	return bits
}

// unconfinedProfile is default-allow with one entry per denial.
func unconfinedProfile(arch string, decisions map[string]*decision) *specs.LinuxSeccomp {
	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow, Architectures: architectures(arch)}
	for _, name := range sortedNames(decisions) {
		d := decisions[name]
		for _, bit := range sortedBits(d.flags) {
			act, errno := action(d.flags[bit], name)
			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{Names: []string{name}, Action: act, ErrnoRet: errno, Args: flagArg(bit)})
		}
		if d.all != "" {
			act, errno := action(d.all, name)
			// With enforced flags, an audited "every call" entry would overlap
			// them with a different action; log only calls without those bits.
			var args []specs.LinuxSeccompArg
			if len(d.flags) > 0 {
				args = []specs.LinuxSeccompArg{{Index: 0, Value: maskOf(d.flags), ValueTwo: 0, Op: specs.OpMaskedEqual}}
			}
			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{Names: []string{name}, Action: act, ErrnoRet: errno, Args: args})
		}
	}
	return profile
}

func maskOf(flags map[uint64]api.RuleMode) uint64 {
	var mask uint64
	for bit := range flags {
		mask |= bit
	}
	return mask
}

// onRuntimeDefault adds denials to a default-deny allowlist without loosening
// it: an enforced syscall is removed from every allow entry; an enforced flag
// narrows the syscall's allow entries to calls without that flag; an audited
// syscall that the base allows is logged instead of silently allowed.
func onRuntimeDefault(base *specs.LinuxSeccomp, decisions map[string]*decision) (*specs.LinuxSeccomp, []string, error) {
	if base.DefaultAction != specs.ActErrno && base.DefaultAction != specs.ActKillProcess && base.DefaultAction != specs.ActKill && base.DefaultAction != specs.ActKillThread {
		return nil, nil, fmt.Errorf("runtime default profile is not default-deny")
	}
	profile := *base
	profile.Architectures = append([]specs.Arch(nil), base.Architectures...)
	profile.Flags = append([]specs.LinuxSeccompFlag(nil), base.Flags...)
	var notes []string
	var extra []specs.LinuxSyscall
	entries := make([]specs.LinuxSyscall, 0, len(base.Syscalls))
	for _, entry := range base.Syscalls {
		entry.Names = append([]string(nil), entry.Names...)
		entry.Args = append([]specs.LinuxSeccompArg(nil), entry.Args...)
		entries = append(entries, entry)
	}
	for _, name := range sortedNames(decisions) {
		d := decisions[name]
		var kept []specs.LinuxSyscall
		for _, entry := range entries {
			if entry.Action != specs.ActAllow || !contains(entry.Names, name) {
				kept = append(kept, entry)
				continue
			}
			rest := entry
			rest.Names = remove(entry.Names, name)
			if len(rest.Names) > 0 {
				kept = append(kept, rest)
			}
			if d.all == api.RuleEnforce {
				continue // only the default deny applies now
			}
			own := entry
			own.Names = []string{name}
			enforced := enforcedMask(d.flags)
			if enforced != 0 {
				narrowed, ok := narrow(own.Args, enforced)
				if !ok {
					return nil, nil, fmt.Errorf("cannot add flag denials to the runtime default rule for %s", name)
				}
				own.Args = narrowed
			}
			audited := maskOf(d.flags) &^ enforced
			if audited != 0 && len(entry.Args) == 0 {
				// Allow calls without the audited bits; the log entries below take
				// the rest, so no two entries overlap with different actions.
				own.Args, _ = narrow(own.Args, audited)
			}
			if d.all == api.RuleAudit {
				if len(own.Args) == 0 {
					own.Action = specs.ActLog
				} else {
					notes = append(notes, fmt.Sprintf("%s: audit applies only where the runtime default allows it unconditionally", name))
				}
			}
			kept = append(kept, own)
			for _, bit := range sortedBits(d.flags) {
				if d.flags[bit] == api.RuleAudit && len(entry.Args) == 0 {
					extra = append(extra, specs.LinuxSyscall{Names: []string{name}, Action: specs.ActLog, Args: flagArg(bit)})
				}
			}
		}
		entries = kept
		if name == "clone3" && d.all == api.RuleEnforce {
			errno := errnoENOSYS
			entries = removeAll(entries, name)
			extra = append(extra, specs.LinuxSyscall{Names: []string{name}, Action: specs.ActErrno, ErrnoRet: &errno})
		}
	}
	profile.Syscalls = append(entries, extra...)
	return &profile, notes, nil
}

func enforcedMask(flags map[uint64]api.RuleMode) uint64 {
	var mask uint64
	for bit, mode := range flags {
		if mode == api.RuleEnforce {
			mask |= bit
		}
	}
	return mask
}

// narrow restricts an allow entry to calls where none of mask's bits are set.
// It only extends an existing "arg0 & m == 0" condition or adds a new one.
func narrow(args []specs.LinuxSeccompArg, mask uint64) ([]specs.LinuxSeccompArg, bool) {
	if len(args) == 0 {
		return []specs.LinuxSeccompArg{{Index: 0, Value: mask, ValueTwo: 0, Op: specs.OpMaskedEqual}}, true
	}
	if len(args) == 1 && args[0].Index == 0 && args[0].Op == specs.OpMaskedEqual && args[0].ValueTwo == 0 {
		return []specs.LinuxSeccompArg{{Index: 0, Value: args[0].Value | mask, ValueTwo: 0, Op: specs.OpMaskedEqual}}, true
	}
	return nil, false
}

// removeAll drops non-allow entries naming only this syscall, so the explicit
// denial added afterwards is the only rule for it.
func removeAll(entries []specs.LinuxSyscall, name string) []specs.LinuxSyscall {
	var out []specs.LinuxSyscall
	for _, entry := range entries {
		if len(entry.Names) == 1 && entry.Names[0] == name {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

func remove(values []string, v string) []string {
	out := make([]string, 0, len(values))
	for _, x := range values {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func appendFlag(flags []specs.LinuxSeccompFlag, flag specs.LinuxSeccompFlag) []specs.LinuxSeccompFlag {
	for _, f := range flags {
		if f == flag {
			return flags
		}
	}
	return append(flags, flag)
}
