// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package privpolicy

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func parse(y string) (Document, error) { return Parse(strings.NewReader(y)) }

func mustParse(t *testing.T, y string) Document {
	t.Helper()
	d, err := parse(y)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func lookup(c Compiled, k KernelKey) (KernelValue, bool) {
	for _, e := range c.Entries {
		if e.Key == k {
			return e.Value, true
		}
	}
	return KernelValue{}, false
}

func TestKernelABISizes(t *testing.T) {
	if n := binary.Size(KernelKey{}); n != KernelKeySize {
		t.Fatalf("key size %d", n)
	}
	if n := binary.Size(KernelValue{}); n != KernelValueSize {
		t.Fatalf("value size %d", n)
	}
}

const sample = `
version: 1
policy:
  mode: audit
  privilege:
    default: allow
    rules:
      - name: no-new-ns
        target: {syscall: [unshare, clone3], flags: [CLONE_NEWNS, CLONE_NEWUSER]}
        action: deny
        mode: enforce
        origin: catalog/G1
      - name: allow-unshare-ns
        target: {syscall: [unshare], flags: [CLONE_NEWNS]}
        action: allow
      - name: audit-sysadmin
        target: {capability: [SYS_ADMIN]}
        action: deny
      - name: no-proc
        target: {mountFsType: [proc]}
        action: deny
        mode: enforce
`

func TestCompileFoldsMostLimiting(t *testing.T) {
	c, err := CompileKernel(mustParse(t, sample), 7)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := lookup(c, KernelKey{Kind: KindMeta})
	// The policy audits, but one rule enforces: the slot enforces.
	if meta.Generation != 7 || meta.Mode != KernelModeEnforce {
		t.Fatalf("meta %+v", meta)
	}
	// Deny+enforce beats the allow on the same key, independent of order.
	v, ok := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["unshare"], Qual: NamespaceFlags["CLONE_NEWNS"]})
	if !ok || v.Rank != RankDenyEnforce || c.RuleNames[v.RuleID] != "no-new-ns" || c.Origins[v.OriginID] != "catalog/G1" {
		t.Fatalf("unshare/NEWNS %+v ok=%v", v, ok)
	}
	// Rule mode inherits the policy mode.
	v, _ = lookup(c, KernelKey{Kind: KindCapability, ID: Capabilities["SYS_ADMIN"]})
	if v.Rank != RankDenyAudit {
		t.Fatalf("SYS_ADMIN rank %d", v.Rank)
	}
	var proc KernelKey
	proc.Kind = KindMountFSType
	copy(proc.Name[:], "proc")
	if v, ok = lookup(c, proc); !ok || v.Rank != RankDenyEnforce {
		t.Fatalf("proc %+v", v)
	}
	// The default covers syscall and mountFsType, never capability.
	if v, ok = lookup(c, KernelKey{Kind: KindDefault, ID: KindSyscall}); !ok || v.Rank != RankAllow || c.RuleNames[v.RuleID] != "default" {
		t.Fatalf("syscall default %+v", v)
	}
	if _, ok = lookup(c, KernelKey{Kind: KindDefault, ID: KindCapability}); ok {
		t.Fatal("capability default must not be written")
	}
	if c.Entries[0].Key.Kind != KindMeta {
		t.Fatal("META must be the first entry")
	}
}

func TestOffLoadsOnlyMeta(t *testing.T) {
	c, err := CompileKernel(mustParse(t, "version: 1\npolicy: {mode: off, privilege: {default: deny}}\n"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 1 || c.Entries[0].Value.Mode != KernelModeOff {
		t.Fatalf("entries %+v", c.Entries)
	}
}

func TestValidationErrors(t *testing.T) {
	base := "version: 1\npolicy:\n  mode: enforce\n  privilege:\n    default: allow\n    rules:\n"
	for name, rule := range map[string]string{
		"two kinds":      "      - {name: r, target: {syscall: [mount], capability: [SYS_ADMIN]}, action: deny}\n",
		"no kind":        "      - {name: r, target: {}, action: deny}\n",
		"flags on cap":   "      - {name: r, target: {capability: [SYS_ADMIN], flags: [CLONE_NEWNS]}, action: deny}\n",
		"flags on mount": "      - {name: r, target: {syscall: [mount], flags: [CLONE_NEWNS]}, action: deny}\n",
		"bad syscall":    "      - {name: r, target: {syscall: [read]}, action: deny}\n",
		"cap prefix":     "      - {name: r, target: {capability: [CAP_SYS_ADMIN]}, action: deny}\n",
		"bad action":     "      - {name: r, target: {syscall: [mount]}, action: block}\n",
		"long fstype":    "      - {name: r, target: {mountFsType: [abcdefghijklmnop]}, action: deny}\n",
		"NUL fstype":     "      - {name: r, target: {mountFsType: [\"pro\\0c\"]}, action: deny}\n",
		"duplicate name": "      - {name: r, target: {syscall: [mount]}, action: deny}\n      - {name: r, target: {syscall: [bpf]}, action: deny}\n",
		"unknown field":  "      - {name: r, target: {path: [/x]}, action: deny}\n",
		"bare clone":     "      - {name: r, target: {syscall: [clone]}, action: deny}\n",
		"bare clone3":    "      - {name: r, target: {syscall: [unshare, clone3]}, action: allow}\n",
	} {
		if _, err := parse(base + rule); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := CompileKernel(mustParse(t, base+"      - {name: r, target: {syscall: [mount]}, action: deny}\n"), 0); err == nil {
		t.Error("zero generation must fail")
	}
}

func TestCompileSlotsMergesPolicies(t *testing.T) {
	a := mustParse(t, "version: 1\nname: a\npolicy:\n  mode: audit\n  privilege:\n    default: deny\n    rules:\n      - {name: no-bpf, target: {syscall: [bpf]}, action: deny, mode: enforce}\n")
	b := mustParse(t, "version: 1\nname: b\npolicy:\n  mode: enforce\n  privilege:\n    default: allow\n    rules:\n      - {name: mount-ok, target: {syscall: [mount]}, action: allow}\n      - {name: bpf-ok, target: {syscall: [bpf]}, action: allow}\n")
	c, err := CompileSlots([][]Document{{a, b}, {b}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if c.Slots != 2 {
		t.Fatalf("slots %d", c.Slots)
	}
	get := func(k KernelKey) KernelValue {
		v, ok := lookup(c, k)
		if !ok {
			t.Fatalf("missing %+v", k)
		}
		return v
	}
	// Merged default: deny (a denies); mode audit, because only a agrees.
	if v := get(KernelKey{Slot: 0, Kind: KindDefault, ID: KindSyscall}); v.Rank != RankDenyAudit {
		t.Fatalf("merged default rank %d", v.Rank)
	}
	// b's allow beats a's default deny; a's explicit deny beats b's allow.
	if v := get(KernelKey{Slot: 0, Kind: KindSyscall, ID: Syscalls["mount"]}); v.Rank != RankAllow {
		t.Fatalf("mount rank %d", v.Rank)
	}
	if v := get(KernelKey{Slot: 0, Kind: KindSyscall, ID: Syscalls["bpf"]}); v.Rank != RankDenyEnforce || c.RuleNames[v.RuleID] != "a/no-bpf" {
		t.Fatalf("bpf %+v %s", v, c.RuleNames[v.RuleID])
	}
	// Slot 1 holds b alone.
	if v := get(KernelKey{Slot: 1, Kind: KindDefault, ID: KindSyscall}); v.Rank != RankAllow {
		t.Fatalf("slot 1 default rank %d", v.Rank)
	}
	// b enforces, but has only allow entries: the slot enforces nothing.
	if v := get(KernelKey{Slot: 1, Kind: KindMeta}); v.Generation != 4 || v.Mode != KernelModeAudit {
		t.Fatalf("slot 1 meta %+v", v)
	}
	// Slot 0 has a's enforce rule: it enforces.
	if v := get(KernelKey{Slot: 0, Kind: KindMeta}); v.Mode != KernelModeEnforce {
		t.Fatalf("slot 0 meta %+v", v)
	}
}

// Policy A: audit deny mount. Policy B: enforce default deny, no mount rule.
// The audit rule must not weaken B's enforce default deny: mount stays blocked.
func TestAuditDenyNeverWeakensEnforceDefaultDeny(t *testing.T) {
	a := mustParse(t, "version: 1\nname: a\npolicy:\n  mode: audit\n  privilege:\n    default: allow\n    rules:\n      - {name: watch-mount, target: {syscall: [mount]}, action: deny}\n")
	b := mustParse(t, "version: 1\nname: b\npolicy:\n  mode: enforce\n  privilege:\n    default: deny\n")
	c, err := CompileSlots([][]Document{{a, b}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["mount"]})
	if !ok || v.Rank != RankDenyEnforce {
		t.Fatalf("mount must stay blocked: %+v", v)
	}
	// Without policy A the result is the same: adding an audit policy never
	// makes the merged result less strict.
	alone, _ := CompileSlots([][]Document{{b}}, 1)
	if d, _ := lookup(alone, KernelKey{Kind: KindDefault, ID: KindSyscall}); d.Rank != RankDenyEnforce {
		t.Fatalf("b alone: %+v", d)
	}
	// An explicit allow still beats another policy's default deny.
	allow := mustParse(t, "version: 1\nname: c\npolicy:\n  mode: enforce\n  privilege:\n    default: allow\n    rules:\n      - {name: mount-ok, target: {syscall: [mount]}, action: allow}\n")
	c, _ = CompileSlots([][]Document{{allow, b}}, 1)
	if v, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["mount"]}); v.Rank != RankAllow {
		t.Fatalf("allow must beat a default deny: %+v", v)
	}
	// One policy alone keeps its own rule mode: its audit rule decides.
	single := mustParse(t, "version: 1\npolicy:\n  mode: enforce\n  privilege:\n    default: deny\n    rules:\n      - {name: watch-mount, target: {syscall: [mount]}, action: deny, mode: audit}\n")
	c, _ = CompileSlots([][]Document{{single}}, 1)
	if v, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["mount"]}); v.Rank != RankDenyAudit {
		t.Fatalf("single policy rule mode: %+v", v)
	}
}

// Namespace syscalls combine {syscall, 0} with each flag key in the program.
// The audit-deny rule must not turn calls that both policies allow or only
// audit into an enforced deny.
func TestAuditDenyRaiseRespectsFlagKeys(t *testing.T) {
	rankOf := func(c Compiled, flag string) uint8 {
		anyFlag, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["unshare"]})
		f, _ := lookup(c, KernelKey{Kind: KindSyscall, ID: Syscalls["unshare"], Qual: NamespaceFlags[flag]})
		return max(anyFlag.Rank, f.Rank)
	}
	// A: audit deny unshare NEWNS. B: enforce default deny, allow unshare (any flag).
	a := mustParse(t, "version: 1\nname: a\npolicy:\n  mode: audit\n  privilege:\n    default: allow\n    rules:\n      - {name: watch-mntns, target: {syscall: [unshare], flags: [CLONE_NEWNS]}, action: deny}\n")
	b := mustParse(t, "version: 1\nname: b\npolicy:\n  mode: enforce\n  privilege:\n    default: deny\n    rules:\n      - {name: unshare-ok, target: {syscall: [unshare]}, action: allow}\n")
	c, err := CompileSlots([][]Document{{a, b}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r := rankOf(c, "CLONE_NEWNS"); r != RankDenyAudit {
		t.Fatalf("unshare -m: rank %d, want audit (B allows, A audits)", r)
	}
	// Mirror: A audit deny unshare (any flag). B: enforce default deny, allow NEWNS.
	a = mustParse(t, "version: 1\nname: a\npolicy:\n  mode: audit\n  privilege:\n    default: allow\n    rules:\n      - {name: watch-unshare, target: {syscall: [unshare]}, action: deny}\n")
	b = mustParse(t, "version: 1\nname: b\npolicy:\n  mode: enforce\n  privilege:\n    default: deny\n    rules:\n      - {name: mntns-ok, target: {syscall: [unshare], flags: [CLONE_NEWNS]}, action: allow}\n")
	c, err = CompileSlots([][]Document{{a, b}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r := rankOf(c, "CLONE_NEWNS"); r == RankDenyEnforce {
		t.Fatal("unshare -m is allowed by B and audited by A: it must not be enforced")
	}
	// B's default deny still applies to flags B does not allow.
	if r := rankOf(c, "CLONE_NEWNET"); r != RankDenyEnforce {
		t.Fatalf("unshare --net: rank %d, want enforce from B's default", r)
	}
}

func TestParse(t *testing.T) {
	f, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := Parse(f)
	if err != nil {
		t.Fatalf("example: %v", err)
	}
	if _, err := CompileKernel(d, 1); err != nil {
		t.Fatalf("example compile: %v", err)
	}
	for name, in := range map[string]string{
		"unknown field": "version: 1\npolicy: {mode: enforce, privilege: {default: allow}}\nbinding: {}\n",
		"two documents": "version: 1\npolicy: {mode: enforce, privilege: {default: allow}}\n---\nversion: 1\n",
		"too large":     "version: 1\n#" + strings.Repeat("x", MaxBytes) + "\n",
	} {
		if _, err := parse(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
