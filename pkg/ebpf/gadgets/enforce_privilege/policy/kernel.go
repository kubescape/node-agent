// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package privpolicy

import (
	"fmt"
	"sort"
)

// Map ABI of ../privilege_policy.h and ../../common/policy.h. Keep in sync.
const (
	// Per node instance: slots, entries per slot and entries in total.
	KernelMaxSlots       = 64
	KernelMaxSlotEntries = 512
	KernelMaxEntries     = 16384
	KernelNameLen        = 16
	KernelKeySize        = 40
	KernelValueSize      = 24

	KindMeta        = 0
	KindDefault     = 1
	KindSyscall     = 2
	KindCapability  = 3
	KindMountFSType = 4

	RankNone          = 0
	RankAllow         = 1
	RankDenyAudit     = 2
	RankDenyEnforce   = 3
	KernelModeOff     = 0
	KernelModeAudit   = 1
	KernelModeEnforce = 2
)

// Syscalls maps policy names to the program's priv_syscall ids.
var Syscalls = map[string]uint32{
	"unshare": 1, "setns": 2, "clone": 3, "clone3": 4, "mount": 5, "umount2": 6,
	"pivot_root": 7, "chroot": 8, "open_tree": 9, "move_mount": 10, "fsopen": 11,
	"fsmount": 12, "fspick": 13, "mount_setattr": 14, "ptrace": 15,
	"process_vm_readv": 16, "process_vm_writev": 17, "init_module": 18,
	"finit_module": 19, "bpf": 20, "perf_event_open": 21, "kexec_load": 22,
	"keyctl": 23, "userfaultfd": 24, "io_uring_setup": 25, "mknod": 26,
	"setuid": 27, "setgid": 28, "capset": 29,
}

var NamespaceSyscalls = map[string]bool{"unshare": true, "setns": true, "clone": true, "clone3": true}

var namespaceSyscallIDs = map[uint32]bool{1: true, 2: true, 3: true, 4: true}

var NamespaceFlags = map[string]uint64{
	"CLONE_NEWNS": 0x00020000, "CLONE_NEWCGROUP": 0x02000000, "CLONE_NEWUTS": 0x04000000,
	"CLONE_NEWIPC": 0x08000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000,
	"CLONE_NEWNET": 0x40000000, "CLONE_NEWTIME": 0x00000080,
}

var Capabilities = map[string]uint32{
	"CHOWN": 0, "DAC_OVERRIDE": 1, "DAC_READ_SEARCH": 2, "FOWNER": 3, "FSETID": 4,
	"KILL": 5, "SETGID": 6, "SETUID": 7, "SETPCAP": 8, "LINUX_IMMUTABLE": 9,
	"NET_BIND_SERVICE": 10, "NET_BROADCAST": 11, "NET_ADMIN": 12, "NET_RAW": 13,
	"IPC_LOCK": 14, "IPC_OWNER": 15, "SYS_MODULE": 16, "SYS_RAWIO": 17,
	"SYS_CHROOT": 18, "SYS_PTRACE": 19, "SYS_PACCT": 20, "SYS_ADMIN": 21,
	"SYS_BOOT": 22, "SYS_NICE": 23, "SYS_RESOURCE": 24, "SYS_TIME": 25,
	"SYS_TTY_CONFIG": 26, "MKNOD": 27, "LEASE": 28, "AUDIT_WRITE": 29,
	"AUDIT_CONTROL": 30, "SETFCAP": 31, "MAC_OVERRIDE": 32, "MAC_ADMIN": 33,
	"SYSLOG": 34, "WAKE_ALARM": 35, "BLOCK_SUSPEND": 36, "AUDIT_READ": 37,
	"PERFMON": 38, "BPF": 39, "CHECKPOINT_RESTORE": 40,
}

// KernelKey and KernelValue match struct policy_key and struct policy_value.
type KernelKey struct {
	Slot uint32
	Kind uint32
	ID   uint32
	_    uint32
	Qual uint64
	Name [KernelNameLen]byte
}

type KernelValue struct {
	Rank       uint8
	_          [3]uint8
	RuleID     uint32
	OriginID   uint32
	Mode       uint32
	Generation uint64
}

type KernelEntry struct {
	Key   KernelKey
	Value KernelValue
}

// Compiled is the frozen map content plus the id tables events refer to.
// RuleNames[0] and Origins[0] are empty: id 0 means none.
type Compiled struct {
	Generation uint64
	// Slots is the number of policy slots (combinations of policies).
	Slots     uint32
	Entries   []KernelEntry
	RuleNames []string
	Origins   []string
}

func rank(action, mode string) uint8 {
	switch {
	case action == "allow":
		return RankAllow
	case mode == "enforce":
		return RankDenyEnforce
	default:
		return RankDenyAudit
	}
}

// CompileKernel compiles one policy into slot 0.
func CompileKernel(d Document, generation uint64) (Compiled, error) {
	return CompileSlots([][]Document{{d}}, generation)
}

// CompileSlots compiles one node instance. Each slot holds one combination of
// documents, combined so that the most limiting result wins:
//   - rules are the union, each with its own name, origin and mode; the compiler
//     folds every rule on one key into the most limiting rank, so an explicit
//     deny beats an allow and an allow beats a default;
//   - a default is deny if any document's default is deny, else allow; its mode
//     is the strictest among the documents whose default equals the merged one;
//   - an audit deny rule never weakens another document's enforce default deny
//     (see the raise below), while an explicit allow still beats it.
//
// The default covers the syscall and mountFsType kinds only. Capability checks
// have no default: only explicit capability rules apply, because capable() runs
// for many benign reasons.
func CompileSlots(slots [][]Document, generation uint64) (Compiled, error) {
	if generation == 0 {
		return Compiled{}, fmt.Errorf("generation must be nonzero")
	}
	if len(slots) > KernelMaxSlots {
		return Compiled{}, fmt.Errorf("%d policy combinations exceed %d per node", len(slots), KernelMaxSlots)
	}
	c := Compiled{Generation: generation, RuleNames: []string{"", "default"}, Origins: []string{""}}
	originIDs := map[string]uint32{}
	originID := func(o string) uint32 {
		if o == "" {
			return 0
		}
		if id, ok := originIDs[o]; ok {
			return id
		}
		c.Origins = append(c.Origins, o)
		originIDs[o] = uint32(len(c.Origins) - 1)
		return originIDs[o]
	}
	for slot, docs := range slots {
		if len(docs) == 0 {
			return Compiled{}, fmt.Errorf("slot %d has no policy", slot)
		}
		entries, err := compileSlot(uint32(slot), docs, generation, &c, originID)
		if err != nil {
			return Compiled{}, err
		}
		if len(entries) > KernelMaxSlotEntries {
			return Compiled{}, fmt.Errorf("policy combination expands to %d map entries (max %d)", len(entries), KernelMaxSlotEntries)
		}
		c.Entries = append(c.Entries, entries...)
	}
	c.Slots = uint32(len(slots))
	if len(c.Entries) > KernelMaxEntries {
		return Compiled{}, fmt.Errorf("policies expand to %d map entries (max %d)", len(c.Entries), KernelMaxEntries)
	}
	return c, nil
}

func compileSlot(slot uint32, docs []Document, generation uint64, c *Compiled, originID func(string) uint32) ([]KernelEntry, error) {
	meta := KernelEntry{Key: KernelKey{Slot: slot, Kind: KindMeta}, Value: KernelValue{Generation: generation}}
	var active []Document
	for _, d := range docs {
		if err := d.Validate(); err != nil {
			return nil, err
		}
		// The META mode is audit for any active document and enforce only
		// when an entry enforces (set below).
		if d.Policy.Mode != "off" {
			meta.Value.Mode = KernelModeAudit
			active = append(active, d)
		}
	}
	if len(active) == 0 {
		return []KernelEntry{meta}, nil
	}

	folded := map[KernelKey]KernelValue{}
	// Per rule key: whether any rule allows, and which policies have a rule.
	allowed := map[KernelKey]bool{}
	ruleOf := map[KernelKey]map[int]bool{}
	doc := 0
	put := func(k KernelKey, v KernelValue) {
		k.Slot = slot
		if old, ok := folded[k]; !ok || v.Rank > old.Rank {
			folded[k] = v
		}
		if k.Kind == KindDefault {
			return
		}
		if v.Rank == RankAllow {
			allowed[k] = true
		}
		if ruleOf[k] == nil {
			ruleOf[k] = map[int]bool{}
		}
		ruleOf[k][doc] = true
	}

	// Merged default: deny if any policy denies; the strictest mode among the
	// policies that agree with the merged verdict.
	merged := "allow"
	for _, d := range active {
		if d.Policy.Privilege.Default == "deny" {
			merged = "deny"
		}
	}
	mode := "audit"
	for _, d := range active {
		if d.Policy.Privilege.Default == merged && d.Policy.Mode == "enforce" {
			mode = "enforce"
		}
	}
	def := KernelValue{Rank: rank(merged, mode), RuleID: 1}
	put(KernelKey{Kind: KindDefault, ID: KindSyscall}, def)
	put(KernelKey{Kind: KindDefault, ID: KindMountFSType}, def)

	for i, d := range active {
		doc = i
		for _, r := range d.Policy.Privilege.Rules {
			mode := r.Mode
			if mode == "" {
				mode = d.Policy.Mode
			}
			name := r.Name
			if d.Name != "" {
				name = d.Name + "/" + r.Name
			}
			c.RuleNames = append(c.RuleNames, name)
			v := KernelValue{Rank: rank(r.Action, mode), RuleID: uint32(len(c.RuleNames) - 1), OriginID: originID(r.Origin)}
			t := r.Target
			for _, sc := range t.Syscall {
				if len(t.Flags) == 0 {
					put(KernelKey{Kind: KindSyscall, ID: Syscalls[sc]}, v)
				}
				for _, f := range t.Flags {
					put(KernelKey{Kind: KindSyscall, ID: Syscalls[sc], Qual: NamespaceFlags[f]}, v)
				}
			}
			for _, cp := range t.Capability {
				put(KernelKey{Kind: KindCapability, ID: Capabilities[cp]}, v)
			}
			for _, fs := range t.MountFSType {
				k := KernelKey{Kind: KindMountFSType}
				copy(k.Name[:], fs)
				put(k, v)
			}
		}
	}

	// A monitoring (audit) deny rule must never weaken another policy's enforce
	// deny, including its default deny: on a key where every matching rule
	// denies, the default deny of each policy without a rule on that key still
	// counts. An explicit allow still beats another policy's default deny.
	//
	// The program combines {syscall, 0} with every {syscall, flag} of a call, so
	// namespace syscalls are handled per flag: a rule on {syscall, 0} also
	// matches every flag, and only the per-flag keys are raised.
	raise := func(k KernelKey, hasRule func(i int) bool) {
		v := folded[k]
		for i, d := range active {
			if d.Policy.Privilege.Default != "deny" || hasRule(i) {
				continue
			}
			if r := rank("deny", d.Policy.Mode); r > v.Rank {
				v = KernelValue{Rank: r, RuleID: 1}
			}
		}
		if v.Rank != RankNone {
			folded[k] = v
		}
	}
	for k := range folded {
		if k.Kind == KindMountFSType || (k.Kind == KindSyscall && !namespaceSyscallIDs[k.ID]) {
			if !allowed[k] {
				raise(k, func(i int) bool { return ruleOf[k][i] })
			}
		}
	}
	for id := range namespaceSyscallIDs {
		anyFlag := KernelKey{Slot: slot, Kind: KindSyscall, ID: id}
		for _, flag := range NamespaceFlags {
			k := anyFlag
			k.Qual = flag
			denied := folded[anyFlag].Rank >= RankDenyAudit || folded[k].Rank >= RankDenyAudit
			if !denied || allowed[anyFlag] || allowed[k] {
				continue
			}
			raise(k, func(i int) bool { return ruleOf[anyFlag][i] || ruleOf[k][i] })
		}
	}

	keys := make([]KernelKey, 0, len(folded))
	for k, v := range folded {
		keys = append(keys, k)
		// The META mode tells the program whether the slot enforces at
		// all: an audit policy can carry an enforce rule, and an enforce
		// policy with only allow entries enforces nothing.
		if v.Rank == RankDenyEnforce {
			meta.Value.Mode = KernelModeEnforce
		}
	}
	entries := []KernelEntry{meta}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Qual != b.Qual {
			return a.Qual < b.Qual
		}
		return string(a.Name[:]) < string(b.Name[:])
	})
	for _, k := range keys {
		entries = append(entries, KernelEntry{Key: k, Value: folded[k]})
	}
	return entries, nil
}
