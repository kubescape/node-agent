// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

type fakePolicyMap struct {
	flags uint32
	puts  int
	keys  []privpolicy.KernelKey
	gone  int
}

func (m *fakePolicyMap) Put(k, _ interface{}) error {
	m.puts++
	m.keys = append(m.keys, k.(privpolicy.KernelKey))
	return nil
}
func (m *fakePolicyMap) Delete(interface{}) error { m.gone++; return nil }
func (m *fakePolicyMap) Type() ebpf.MapType       { return ebpf.Hash }
func (m *fakePolicyMap) KeySize() uint32          { return privpolicy.KernelKeySize }
func (m *fakePolicyMap) ValueSize() uint32        { return privpolicy.KernelValueSize }
func (m *fakePolicyMap) MaxEntries() uint32       { return privpolicy.KernelMapEntries }
func (m *fakePolicyMap) Flags() uint32            { return m.flags }
func (m *fakePolicyMap) Freeze() error            { return nil }

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

func TestPublicationsWriteByStorageHeaderLast(t *testing.T) {
	c := compiled(t)
	pubs := Publications(c)
	if len(pubs) != 1 || pubs[0].Slot != 0 || pubs[0].Generation != 5 || !pubs[0].Strict {
		t.Fatalf("publications: %+v", pubs)
	}
	m := &fakePolicyMap{flags: unix.BPF_F_RDONLY_PROG}
	maps := map[string]enforcement.Map{policyMap: m}
	if err := pubs[0].Write(maps, 7); err != nil || m.puts != len(c.Entries) {
		t.Fatalf("write: %v puts=%d", err, m.puts)
	}
	for _, k := range m.keys {
		if k.Slot != 7 {
			t.Fatalf("an entry is not keyed by the storage index: %+v", k)
		}
	}
	if last := m.keys[len(m.keys)-1]; last.Kind != privpolicy.KindMeta {
		t.Fatalf("the META entry must be written last: %+v", last)
	}
	if err := pubs[0].Delete(maps, 7); err != nil || m.gone != len(c.Entries) {
		t.Fatalf("delete: %v gone=%d", err, m.gone)
	}
	if err := pubs[0].Write(map[string]enforcement.Map{policyMap: &fakePolicyMap{}}, 7); err == nil {
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
		if len(Hooks[m[1]]) > 1 {
			// Two signatures: the program reads ctx itself (see the
			// security_list_options type matches in the program).
			if strings.TrimSpace(m[2]) != "" {
				t.Errorf("hook %s has two signatures and must not name arguments", m[1])
			}
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(m[2]), "int ret") {
			t.Errorf("hook %s does not end with int ret", m[1])
		}
		if args := strings.Count(m[2], ",") - 1; len(Hooks[m[1]]) != 1 || Hooks[m[1]][0] != args {
			t.Errorf("hook %s: program has %d arguments, Hooks has %v", m[1], args, Hooks[m[1]])
		}
	}
	if len(seen) != len(Hooks) {
		t.Errorf("program has %d int hooks, Hooks has %d", len(seen), len(Hooks))
	}
}

func TestStrictSlots(t *testing.T) {
	enforce := privpolicy.Document{Version: 1, Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow",
		Rules: []privpolicy.Rule{{Name: "r", Action: "deny", Target: privpolicy.Target{Syscall: []string{"mount"}}}}}}}
	audit := enforce
	audit.Policy.Mode = "audit"
	c, err := privpolicy.CompileSlots([][]privpolicy.Document{{audit}, {enforce}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	strict := StrictSlots(c)
	if strict(0) || !strict(1) || strict(2) {
		t.Fatalf("strict slots: %v %v %v", strict(0), strict(1), strict(2))
	}
}
