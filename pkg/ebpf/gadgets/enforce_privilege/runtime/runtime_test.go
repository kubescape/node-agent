// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

type fakePolicyMap struct {
	flags uint32
	puts  int
}

func (m *fakePolicyMap) Put(_, _ interface{}) error { m.puts++; return nil }
func (m *fakePolicyMap) Delete(interface{}) error   { return nil }
func (m *fakePolicyMap) Type() ebpf.MapType         { return ebpf.Hash }
func (m *fakePolicyMap) KeySize() uint32            { return privpolicy.KernelKeySize }
func (m *fakePolicyMap) ValueSize() uint32          { return privpolicy.KernelValueSize }
func (m *fakePolicyMap) MaxEntries() uint32         { return privpolicy.KernelMaxEntries }
func (m *fakePolicyMap) Flags() uint32              { return m.flags }
func (m *fakePolicyMap) Freeze() error              { return nil }

func compiled(t *testing.T) privpolicy.Compiled {
	t.Helper()
	d := privpolicy.Document{Version: 1, Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow",
		Rules: []privpolicy.Rule{{Name: "r", Action: "deny", Target: privpolicy.Target{Syscall: []string{"mount"}}}}}}}
	c, err := privpolicy.CompileKernel(d, 5)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWritePolicyChecksLayout(t *testing.T) {
	c := compiled(t)
	m := &fakePolicyMap{flags: unix.BPF_F_RDONLY_PROG}
	if err := writePolicy(c.Entries)(m); err != nil || m.puts != len(c.Entries) {
		t.Fatalf("write: %v puts=%d", err, m.puts)
	}
	if err := writePolicy(c.Entries)(&fakePolicyMap{}); err == nil {
		t.Fatal("writable policy map must be rejected")
	}
}

func TestValidateConfig(t *testing.T) {
	c := compiled(t)
	if err := validateConfig(Config{Policy: c}); err != nil {
		t.Fatal(err)
	}
	c.Generation = 9
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("generation mismatch must fail")
	}
	c = compiled(t)
	c.Slots = 2
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("a slot without its generation entry must fail")
	}
	c.Entries = append(c.Entries, c.Entries[0]) // a second slot-0 entry, no slot 1
	if err := validateConfig(Config{Policy: c}); err == nil {
		t.Fatal("duplicate generation entries must fail")
	}
}
