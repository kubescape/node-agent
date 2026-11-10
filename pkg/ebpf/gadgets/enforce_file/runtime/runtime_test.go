// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"golang.org/x/sys/unix"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

type fakeMap struct {
	typ             ebpf.MapType
	key, value, max uint32
	flags           uint32
	puts            int
	frozen          bool
	slotFlags       []uint32
}

func (m *fakeMap) Put(_, v interface{}) error {
	m.puts++
	if s, ok := v.(*filepolicy.SlotValue); ok {
		m.slotFlags = append(m.slotFlags, s.Flags)
	}
	return nil
}
func (m *fakeMap) Delete(interface{}) error { return nil }
func (m *fakeMap) Type() ebpf.MapType       { return m.typ }
func (m *fakeMap) KeySize() uint32          { return m.key }
func (m *fakeMap) ValueSize() uint32        { return m.value }
func (m *fakeMap) MaxEntries() uint32       { return m.max }
func (m *fakeMap) Flags() uint32            { return m.flags }
func (m *fakeMap) Freeze() error            { m.frozen = true; return nil }

func compiled(t *testing.T) filepolicy.Compiled {
	t.Helper()
	f, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := filepolicy.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	c, err := filepolicy.CompileKernel(d, 5)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWriteChecksLayout(t *testing.T) {
	c := compiled(t)
	ro := uint32(unix.BPF_F_RDONLY_PROG)
	slots := &fakeMap{typ: ebpf.Array, key: 4, value: filepolicy.KernelSlotSize, max: filepolicy.KernelMaxSlots, flags: ro}
	literals := &fakeMap{typ: ebpf.Hash, key: filepolicy.KernelLiteralKeySize, value: filepolicy.KernelLiteralValueSize, max: filepolicy.KernelMaxLiterals, flags: ro}
	if err := writeSlots(c.Slots, true)(slots); err != nil || slots.puts != len(c.Slots) || slots.slotFlags[0] != filepolicy.SlotFromImage {
		t.Fatalf("slots: %v puts=%d flags=%v", err, slots.puts, slots.slotFlags)
	}
	// Without a verified overlay layout no slot judges fromImage, whatever
	// the compiled value says.
	c.Slots[0].Flags = filepolicy.SlotFromImage
	noImage := *slots
	noImage.slotFlags = nil
	if err := writeSlots(c.Slots, false)(&noImage); err != nil || noImage.slotFlags[0] != 0 {
		t.Fatalf("slots without fromImage: %v flags=%v", err, noImage.slotFlags)
	}
	if err := writeLiterals(literals, c); err != nil || literals.puts != len(c.Literals) || !literals.frozen {
		t.Fatalf("literals: %v puts=%d frozen=%v", err, literals.puts, literals.frozen)
	}
	writable := *literals
	writable.flags = 0
	if err := writeLiterals(&writable, c); err == nil {
		t.Fatal("a map the program can write must be rejected")
	}
	small := *slots
	small.value--
	if err := writeSlots(c.Slots, true)(&small); err == nil {
		t.Fatal("a slot map of another value size must be rejected")
	}
	if err := writeLiterals(nil, c); err == nil {
		t.Fatal("a missing map must be rejected")
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(Config{Policy: compiled(t)}); err != nil {
		t.Fatal(err)
	}
	// An empty instance (no slot yet) is valid.
	empty, err := filepolicy.CompileSlots(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(Config{Policy: empty}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*filepolicy.Compiled){
		"generation mismatch": func(c *filepolicy.Compiled) { c.Generation = 9 },
		"literal of no slot":  func(c *filepolicy.Compiled) { c.Literals[0].Key.Slot = 1 },
		"too many rules":      func(c *filepolicy.Compiled) { c.Slots[0].NRules = filepolicy.KernelMaxRules + 1 },
		"too many globs":      func(c *filepolicy.Compiled) { c.Slots[0].NGlobs = filepolicy.KernelMaxGlobs + 1 },
		"unknown rule name":   func(c *filepolicy.Compiled) { c.RuleNames = c.RuleNames[:2] },
		"generation zero":     func(c *filepolicy.Compiled) { c.Generation = 0 },
	} {
		c := compiled(t)
		mutate(&c)
		if err := validateConfig(Config{Policy: c}); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
}

func TestWithConfigCopies(t *testing.T) {
	c := compiled(t)
	config := Config{Policy: c}
	WithConfig(config)
	if &config.Policy.Slots[0] != &c.Slots[0] {
		t.Fatal("caller slice must stay untouched")
	}
}

// fakeBTF answers TypeByName for structs.
type fakeBTF map[string]*btf.Struct

func (f fakeBTF) TypeByName(name string, typ any) error {
	s, ok := f[name]
	if !ok {
		return fmt.Errorf("type %s: %w", name, btf.ErrNotFound)
	}
	*typ.(**btf.Struct) = s
	return nil
}

// overlayBTF builds struct ovl_inode as BTF shows it on 6.8 (inode 632 bytes)
// and 6.12 (624 bytes): flags, then vfs_inode at byte 32, __upperdentry, oe.
func overlayBTF(inodeSize uint32, oeGap btf.Bits, withOE bool) fakeBTF {
	inode := &btf.Struct{Name: "inode", Size: inodeSize}
	entry := &btf.Struct{Name: "ovl_entry", Size: 8, Members: []btf.Member{
		{Name: "__numlower", Type: &btf.Int{Name: "unsigned int", Size: 4}, Offset: 0},
		{Name: "__lowerstack", Type: &btf.Array{}, Offset: 64},
	}}
	dentry := &btf.Pointer{Target: &btf.Struct{Name: "dentry"}}
	end := btf.Bits(256 + inodeSize*8)
	members := []btf.Member{
		{Name: "flags", Type: &btf.Int{Size: 8}, Offset: 192},
		{Name: "vfs_inode", Type: inode, Offset: 256},
		{Name: "__upperdentry", Type: dentry, Offset: end},
	}
	if withOE {
		members = append(members, btf.Member{Name: "oe", Type: &btf.Pointer{Target: entry}, Offset: end + oeGap})
	}
	return fakeBTF{"ovl_inode": {Name: "ovl_inode", Members: members}}
}

func TestOverlayLayout(t *testing.T) {
	for _, size := range []uint32{624, 632} {
		if err := checkOverlayLayout(overlayBTF(size, 64, true)); err != nil {
			t.Errorf("inode size %d: %v", size, err)
		}
	}
	// Another field between __upperdentry and oe, a kernel before 6.5 (no
	// oe, a lower inode pointer instead), no overlay BTF: not readable.
	for name, spec := range map[string]fakeBTF{
		"moved oe": overlayBTF(624, 128, true), "no oe": overlayBTF(624, 64, false), "no overlay": {},
	} {
		if err := checkOverlayLayout(spec); err == nil {
			t.Errorf("%s: layout accepted", name)
		}
	}
}

// findFunc answers TypeByName with a fixed error.
type findFunc func(name string) error

func (f findFunc) TypeByName(name string, _ any) error { return f(name) }

func TestOldSetxattrSemantics(t *testing.T) {
	missing := fmt.Errorf("x: %w", btf.ErrNotFound)
	for name, c := range map[string]struct {
		skipcap, ima error
		one, bad     bool
	}{
		"6.11 and later":   {ima: missing},
		"6.9 and 6.10":     {skipcap: missing},
		"before 6.9":       {skipcap: missing, ima: missing, one: true},
		"BTF error":        {skipcap: fmt.Errorf("broken"), bad: true},
		"BTF error on IMA": {skipcap: missing, ima: fmt.Errorf("broken"), bad: true},
	} {
		one, err := oldSetxattrSemantics(findFunc(func(n string) error {
			if n == "bpf_lsm_inode_xattr_skipcap" {
				return c.skipcap
			}
			if n == "bpf_lsm_file_post_open" {
				return c.ima
			}
			return fmt.Errorf("unexpected %q", n)
		}))
		if one != c.one || (err != nil) != c.bad {
			t.Errorf("%s: got %v, %v", name, one, err)
		}
	}
}

// TestHooksMatchProgram keeps Hooks in step with the BPF_PROG signatures: every
// int hook ends with `int ret`, after the listed number of arguments.
func TestHooksMatchProgram(t *testing.T) {
	data, err := os.ReadFile("../program.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	programs := regexp.MustCompile(`SEC\("lsm/(\w+)"\)\s*\nint BPF_PROG\(\w+((?:,[^)]*)?)\)`).FindAllStringSubmatch(string(data), -1)
	seen := map[string]bool{}
	for _, m := range programs {
		if m[1] == "bprm_committed_creds" { // void hook: no verdict
			continue
		}
		seen[m[1]] = true
		if !strings.HasSuffix(strings.TrimSpace(m[2]), "int ret") {
			t.Errorf("hook %s does not end with int ret", m[1])
		}
		if args := strings.Count(m[2], ",") - 1; Hooks[m[1]] != args {
			t.Errorf("hook %s: program has %d arguments, Hooks has %d", m[1], args, Hooks[m[1]])
		}
	}
	if len(seen) != len(Hooks) {
		t.Errorf("program has %d int hooks, Hooks has %d", len(seen), len(Hooks))
	}
}

// Ready refuses activation when the root barrier fails and an initial binding
// is on an enforcing slot. With audit-only initial bindings the instance
// starts, and the barrier error is kept for the owner.
func TestReadyRootBarrier(t *testing.T) {
	c := compiled(t)
	enforce, audit := c.Slots[0], c.Slots[0]
	enforce.Mode, audit.Mode = filepolicy.KernelModeEnforce, filepolicy.KernelModeAudit
	c.Slots = []filepolicy.SlotValue{enforce, audit}
	if !Enforcing(c, 0) || Enforcing(c, 1) || Enforcing(c, 2) {
		t.Fatal("Enforcing does not follow the slot mode")
	}
	failed := fmt.Errorf("no live LSM link")
	defer func(v func(operators.GadgetContext, []rootbarrier.Hook) error) { verifyBarrier = v }(verifyBarrier)

	newInstance := func(t *testing.T, slots ...uint32) *instance {
		t.Helper()
		var initial []enforcement.Binding
		for i, s := range slots {
			initial = append(initial, enforcement.Binding{Slot: s, Container: enforcement.ContainerIdentity{
				Runtime: "docker", ID: fmt.Sprint("c", i), CgroupID: uint64(100 + i), CgroupPath: fmt.Sprint("/c", i)}})
		}
		b, err := enforcement.New(enforcement.Config{Name: operatorName, Generation: c.Generation, Slots: 2,
			InitialBindings: initial, PolicyMap: "file_slots", WritePolicy: func(enforcement.Map) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		return &instance{Bindings: b, policy: c, initial: initial, barrier: &Barrier{}}
	}

	verifyBarrier = func(operators.GadgetContext, []rootbarrier.Hook) error { return failed }
	i := newInstance(t, 1, 0)
	if err := i.Ready(nil); err == nil || !strings.Contains(err.Error(), "no live LSM link") {
		t.Fatalf("enforcing initial binding: want the barrier error, got %v", err)
	}
	if i.barrier.Err() == nil {
		t.Fatal("a refused instance reports an attested barrier")
	}

	// The binding controller of these instances never started, so Ready
	// ends with its error; the barrier must not be the reason.
	notRunning := "binding controller is not running"
	i = newInstance(t, 1)
	if err := i.Ready(nil); err == nil || err.Error() != notRunning {
		t.Fatalf("audit-only initial binding: Ready must go on to the controller, got %v", err)
	}
	if err := i.barrier.Err(); err == nil || !strings.Contains(err.Error(), "no live LSM link") {
		t.Fatalf("audit-only initial binding: want the barrier error kept, got %v", err)
	}

	verifyBarrier = func(operators.GadgetContext, []rootbarrier.Hook) error { return nil }
	i = newInstance(t, 0)
	if err := i.Ready(nil); err == nil || err.Error() != notRunning {
		t.Fatalf("attested barrier: Ready must go on to the controller, got %v", err)
	}
	if err := i.barrier.Err(); err != nil {
		t.Fatalf("attested barrier: %v", err)
	}
}

// The load-time hook check covers the barrier's hooks too, with the same
// count for the hook both use.
func TestAllHooksIncludeRootBarrier(t *testing.T) {
	all := allHooks()
	for _, h := range rootbarrier.Hooks {
		if all[h.LSM] != h.Args {
			t.Errorf("%s: %d arguments, want %d", h.LSM, all[h.LSM], h.Args)
		}
		if n, ok := Hooks[h.LSM]; ok && n != h.Args {
			t.Errorf("%s: the file program and the barrier disagree (%d, %d)", h.LSM, n, h.Args)
		}
	}
	for name, n := range Hooks {
		if all[name] != n {
			t.Errorf("%s missing from the load-time check", name)
		}
	}
}

// TestBarrierHooksAreAttestable: the kernel keeps 15 characters of a program
// name, and attestation matches the kernel's name.
func TestBarrierHooksAreAttestable(t *testing.T) {
	for _, h := range BarrierHooks {
		if len(h.Program) > 15 {
			t.Errorf("program %q of hook %s is longer than the kernel keeps", h.Program, h.LSM)
		}
	}
}
