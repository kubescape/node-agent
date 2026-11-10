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
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
)

type fakeMap struct {
	typ             ebpf.MapType
	key, value, max uint32
	flags           uint32
	puts            int
	frozen          bool
	name            string
	log             *[]string
	data            map[interface{}]interface{}
}

func (m *fakeMap) Put(k, v interface{}) error {
	m.puts++
	if m.log != nil {
		*m.log = append(*m.log, m.name)
	}
	if m.data != nil {
		m.data[k] = v
	}
	return nil
}
func (m *fakeMap) Delete(k interface{}) error {
	if m.data != nil {
		delete(m.data, k)
	}
	return nil
}
func (m *fakeMap) Type() ebpf.MapType { return m.typ }
func (m *fakeMap) KeySize() uint32    { return m.key }
func (m *fakeMap) ValueSize() uint32  { return m.value }
func (m *fakeMap) MaxEntries() uint32 { return m.max }
func (m *fakeMap) Flags() uint32      { return m.flags }
func (m *fakeMap) Freeze() error      { m.frozen = true; return nil }

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

func TestPublicationWritesOneSlotByStorage(t *testing.T) {
	deny := netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: "enforce", Egress: netpolicy.Section{Default: "allow",
		Rules: []netpolicy.Rule{{Name: "r", Action: "deny", CIDRs: []string{"192.0.2.0/24"}}}}}}
	audit := deny
	audit.Policy.Mode = "audit"
	c, err := netpolicy.CompileSlots([][]netpolicy.Document{{audit}, {deny}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	split := splitSlots(c)
	if len(split) != 2 || len(split[1].lists) == 0 {
		t.Fatalf("split: %+v", split)
	}
	ro := uint32(unix.BPF_F_RDONLY_PROG)
	log := &[]string{}
	slots := &fakeMap{typ: ebpf.Array, key: 4, value: netpolicy.KernelSlotSize, max: netpolicy.KernelStorage, flags: ro, name: "slots", log: log, data: map[interface{}]interface{}{}}
	prefixes := &fakeMap{typ: ebpf.LPMTrie, key: netpolicy.KernelPrefixKeySize, value: 4, max: netpolicy.KernelMapPrefixes, flags: ro, name: "prefixes", log: log, data: map[interface{}]interface{}{}}
	lists := &fakeMap{typ: ebpf.Array, key: 4, value: netpolicy.KernelListSize, max: netpolicy.KernelMapLists, flags: ro, name: "lists", log: log, data: map[interface{}]interface{}{}}
	maps := map[string]enforcement.Map{"net_slots": slots, "net_prefix": prefixes, "net_rules": lists}
	i := &instance{lists: newListPool()}
	pub := i.publication(1, split[1])
	if !pub.Strict || pub.Generation != 5 {
		t.Fatalf("publication: %+v", pub)
	}
	if err := pub.Write(maps, 3); err != nil {
		t.Fatal(err)
	}
	if (*log)[len(*log)-1] != "slots" {
		t.Fatalf("the slot header must be written last: %v", *log)
	}
	for k := range prefixes.data {
		if k.(netpolicy.PrefixKey).Slot != 3 {
			t.Fatalf("a prefix is not keyed by the storage index: %+v", k)
		}
	}
	if err := pub.Write(maps, 3); err == nil {
		t.Fatal("a storage index that holds lists must not be written again")
	}
	// Another publication cannot take the storage, and its cleanup must not
	// release lists it did not take.
	other := i.publication(1, split[1])
	if err := other.Write(maps, 3); err == nil {
		t.Fatal("a second publication must not take the same storage")
	}
	if err := other.Delete(maps, 3); err != nil || len(i.lists.used[3]) == 0 || len(prefixes.data) == 0 {
		t.Fatalf("a cleanup must not touch a storage it did not take: %v", err)
	}
	if err := pub.Delete(maps, 3); err != nil || len(prefixes.data) != 0 {
		t.Fatalf("delete: %v %v", err, prefixes.data)
	}
	if len(i.lists.free) != netpolicy.KernelMapLists {
		t.Fatalf("delete must release the lists: %d free", len(i.lists.free))
	}
	writable := *prefixes
	writable.flags = 0
	maps["net_prefix"] = &writable
	if err := pub.Write(maps, 3); err == nil {
		t.Fatal("a map the program can write must be rejected")
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(Config{Policy: compiled(t)}); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(Config{Policy: netpolicy.Compiled{Generation: 1}}); err != nil {
		t.Fatalf("an instance with no slot is valid: %v", err)
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

// TestHooksMatchProgram keeps Hooks in step with the BPF_PROG signatures: every
// int LSM hook ends with `int ret`, after the listed number of arguments.
func TestHooksMatchProgram(t *testing.T) {
	data, err := os.ReadFile("../program.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	programs := regexp.MustCompile(`SEC\("lsm/(\w+)"\)\s*\nint BPF_PROG\(\w+((?:,[^)]*)?)\)`).FindAllStringSubmatch(string(data), -1)
	seen := map[string]bool{}
	for _, m := range programs {
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
