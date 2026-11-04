// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
)

type fakeMap struct {
	typ             ebpf.MapType
	key, value, max uint32
	flags           uint32
	puts            int
	frozen          bool
}

func (m *fakeMap) Put(_, _ interface{}) error { m.puts++; return nil }
func (m *fakeMap) Delete(interface{}) error   { return nil }
func (m *fakeMap) Type() ebpf.MapType         { return m.typ }
func (m *fakeMap) KeySize() uint32            { return m.key }
func (m *fakeMap) ValueSize() uint32          { return m.value }
func (m *fakeMap) MaxEntries() uint32         { return m.max }
func (m *fakeMap) Flags() uint32              { return m.flags }
func (m *fakeMap) Freeze() error              { m.frozen = true; return nil }

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
	if err := writeSlots(c.Slots)(slots); err != nil || slots.puts != len(c.Slots) {
		t.Fatalf("slots: %v puts=%d", err, slots.puts)
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
	if err := writeSlots(c.Slots)(&small); err == nil {
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
	for name, mutate := range map[string]func(*filepolicy.Compiled){
		"generation mismatch": func(c *filepolicy.Compiled) { c.Generation = 9 },
		"literal of no slot":  func(c *filepolicy.Compiled) { c.Literals[0].Key.Slot = 1 },
		"too many rules":      func(c *filepolicy.Compiled) { c.Slots[0].NRules = filepolicy.KernelMaxRules + 1 },
		"too many globs":      func(c *filepolicy.Compiled) { c.Slots[0].NGlobs = filepolicy.KernelMaxGlobs + 1 },
		"unknown rule name":   func(c *filepolicy.Compiled) { c.RuleNames = c.RuleNames[:2] },
		"no slot":             func(c *filepolicy.Compiled) { c.Slots = nil },
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
