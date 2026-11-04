// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
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

func compiled(t *testing.T) netpolicy.Compiled {
	t.Helper()
	d := netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: "enforce", Egress: netpolicy.Section{Default: "allow",
		Rules: []netpolicy.Rule{{Name: "r", Action: "deny", CIDRs: []string{"192.0.2.0/24"}}}}}}
	c, err := netpolicy.CompileKernel(d, 5)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWriteChecksLayout(t *testing.T) {
	c := compiled(t)
	ro := uint32(unix.BPF_F_RDONLY_PROG)
	slots := &fakeMap{typ: ebpf.Array, key: 4, value: netpolicy.KernelSlotSize, max: netpolicy.KernelMaxSlots, flags: ro}
	prefixes := &fakeMap{typ: ebpf.LPMTrie, key: netpolicy.KernelPrefixKeySize, value: 4, max: netpolicy.KernelMaxPrefixes, flags: ro}
	lists := &fakeMap{typ: ebpf.Array, key: 4, value: netpolicy.KernelListSize, max: netpolicy.KernelMaxLists, flags: ro}
	if err := writeSlots(c.Slots)(slots); err != nil || slots.puts != len(c.Slots) {
		t.Fatalf("slots: %v puts=%d", err, slots.puts)
	}
	if err := writeRules(prefixes, lists, c); err != nil || prefixes.puts != len(c.Prefixes) || lists.puts != len(c.Lists) {
		t.Fatalf("rules: %v", err)
	}
	if !prefixes.frozen || !lists.frozen {
		t.Fatal("rule maps must be frozen")
	}
	writable := *prefixes
	writable.flags = 0
	if err := writeRules(&writable, lists, c); err == nil {
		t.Fatal("a map the program can write must be rejected")
	}
	if err := writeRules(nil, lists, c); err == nil {
		t.Fatal("a missing map must be rejected")
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(Config{Policy: compiled(t)}); err != nil {
		t.Fatal(err)
	}
	c := compiled(t)
	c.Generation = 9
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("generation mismatch must fail")
	}
	c = compiled(t)
	c.Prefixes[0].Key.Slot = 1
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("a prefix of a missing slot must fail")
	}
	c = compiled(t)
	c.Prefixes[0].List = uint32(len(c.Lists))
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("a prefix of a missing rule list must fail")
	}
}
