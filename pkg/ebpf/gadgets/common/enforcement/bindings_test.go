// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	"golang.org/x/sys/unix"
)

type fakeMap struct {
	typ                   ebpf.MapType
	key, value, max, flag uint32
	data                  map[interface{}]interface{}
	frozen                bool
	log                   *[]string
	name                  string
	deleteErr, putErr     error
}

func (m *fakeMap) Put(k, v interface{}) error {
	if m.putErr != nil {
		return m.putErr
	}
	if m.frozen {
		return unix.EPERM
	}
	*m.log = append(*m.log, "put "+m.name)
	m.data[k] = v
	return nil
}

func (m *fakeMap) Delete(k interface{}) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.data[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.data, k)
	return nil
}
func (m *fakeMap) Type() ebpf.MapType { return m.typ }
func (m *fakeMap) KeySize() uint32    { return m.key }
func (m *fakeMap) ValueSize() uint32  { return m.value }
func (m *fakeMap) MaxEntries() uint32 { return m.max }
func (m *fakeMap) Flags() uint32      { return m.flag }
func (m *fakeMap) Freeze() error {
	*m.log = append(*m.log, "freeze "+m.name)
	m.frozen = true
	return nil
}

var identity = ContainerIdentity{Runtime: "docker", ID: "abc", CgroupID: 42, CgroupPath: "/system.slice/docker-abc.scope"}

func newFixture(t *testing.T, write func(Map) error) (*Bindings, *fakeMap, *fakeMap, *[]string) {
	t.Helper()
	log := &[]string{}
	policy := &fakeMap{typ: ebpf.Hash, data: map[interface{}]interface{}{}, log: log, name: "policy"}
	members := &fakeMap{typ: ebpf.Hash, key: 8, value: 8, max: MaxBindings, data: map[interface{}]interface{}{}, log: log, name: "bindings"}
	b, err := New(Config{Name: "test", Generation: 5, Slots: 2, PolicyMap: "policy", WritePolicy: write, InitialBindings: []Binding{{Container: identity}}})
	if err != nil {
		t.Fatal(err)
	}
	return b, policy, members, log
}

func TestFreezeBeforeBindAndLifecycle(t *testing.T) {
	b, policy, members, log := newFixture(t, func(m Map) error { return m.Put(uint32(0), uint32(1)) })
	armed := &fakeMap{typ: ebpf.TaskStorage}
	var armedPaths []string
	b.armExisting = func(_ Map, path string) error { armedPaths = append(armedPaths, path); return nil }
	if err := b.start(policy, members, armed, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Ready(nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*log, ","); got != "put policy,freeze policy,put bindings" {
		t.Fatalf("order %s", got)
	}
	if len(armedPaths) != 1 || armedPaths[0] != identity.CgroupPath {
		t.Fatalf("armed %v", armedPaths)
	}
	st := b.Status()
	if !st.Ready || st.Bound != 1 || st.Revision != 5 {
		t.Fatalf("status %+v", st)
	}
	if err := b.Bind(Binding{Container: identity}); err != nil {
		t.Fatal(err)
	}
	// Moving to another slot is one map write, and it arms again: the old
	// slot may have left a task unarmed.
	if err := b.Bind(Binding{Container: identity, Slot: 1}); err != nil || members.data[uint64(42)] != (bindingValue{Slot: 1}) || len(armedPaths) != 2 {
		t.Fatalf("slot move: %v %v armed=%v", err, members.data, armedPaths)
	}
	// A move whose arming fails is undone, so a retry moves and arms again.
	b.armExisting = func(Map, string) error { return errors.New("walk failed") }
	if err := b.Bind(Binding{Container: identity, Slot: 0}); err == nil || members.data[uint64(42)] != (bindingValue{Slot: 1}) {
		t.Fatalf("failed move: %v %v", err, members.data)
	}
	b.armExisting = func(_ Map, path string) error { armedPaths = append(armedPaths, path); return nil }
	if err := b.Bind(Binding{Container: identity, Slot: 2}); err == nil {
		t.Fatal("slot out of range must fail")
	}
	other := identity
	other.ID = "def"
	if err := b.Bind(Binding{Container: other}); err == nil {
		t.Fatal("conflicting cgroup identity must fail")
	}
	if err := b.Unbind(other); err != nil || len(members.data) != 1 {
		t.Fatalf("stale unbind: %v %v", err, members.data)
	}
	if err := b.Unbind(identity); err != nil || len(members.data) != 0 {
		t.Fatalf("unbind: %v %v", err, members.data)
	}
}

func TestFailedArmingRemovesBinding(t *testing.T) {
	b, policy, members, _ := newFixture(t, func(Map) error { return nil })
	b.armExisting = func(Map, string) error { return errors.New("no cgroup") }
	if err := b.start(policy, members, &fakeMap{typ: ebpf.TaskStorage}, nil); err == nil {
		t.Fatal("arming failure must fail startup")
	}
	if len(members.data) != 0 {
		t.Fatalf("binding must be removed: %v", members.data)
	}
}

// When arming fails and the kernel entry cannot be removed, the binding stays
// tracked. A retry with the same slot must arm again, not return early.
func TestSameSlotRetryArmsAfterFailedArming(t *testing.T) {
	b, policy, members, _ := newFixture(t, func(Map) error { return nil })
	b.config.InitialBindings, b.desired = nil, map[execpolicy.Container]Binding{}
	arms := 0
	b.armExisting = func(Map, string) error { arms++; return nil }
	if err := b.start(policy, members, &fakeMap{typ: ebpf.TaskStorage}, nil); err != nil {
		t.Fatal(err)
	}
	b.armExisting = func(Map, string) error { arms++; return errors.New("walk failed") }
	members.deleteErr = errors.New("busy")
	if err := b.Bind(Binding{Container: identity}); err == nil {
		t.Fatal("a failed arming must fail the bind")
	}
	b.armExisting = func(Map, string) error { arms++; return nil }
	members.deleteErr = nil
	if err := b.Bind(Binding{Container: identity}); err != nil || arms != 2 {
		t.Fatalf("retry must arm: %v arms=%d", err, arms)
	}
	if err := b.Bind(Binding{Container: identity}); err != nil || arms != 2 {
		t.Fatalf("an armed binding needs no new arming: %v arms=%d", err, arms)
	}
}

// A slot move whose arming fails and whose rollback also fails keeps the new
// slot tracked. A later retry with that slot must arm again.
func TestSlotMoveRetryArmsAfterFailedRollback(t *testing.T) {
	b, policy, members, _ := newFixture(t, func(Map) error { return nil })
	arms := 0
	b.armExisting = func(Map, string) error { arms++; return nil }
	if err := b.start(policy, members, &fakeMap{typ: ebpf.TaskStorage}, nil); err != nil {
		t.Fatal(err)
	}
	b.armExisting = func(Map, string) error {
		arms++
		members.putErr = errors.New("busy") // the rollback write fails
		return errors.New("walk failed")
	}
	if err := b.Bind(Binding{Container: identity, Slot: 1}); err == nil {
		t.Fatal("a failed move must fail the bind")
	}
	members.putErr = nil
	b.armExisting = func(Map, string) error { arms++; return nil }
	if err := b.Bind(Binding{Container: identity, Slot: 1}); err != nil || arms != 3 {
		t.Fatalf("retry must arm: %v arms=%d", err, arms)
	}
	if members.data[uint64(42)] != (bindingValue{Slot: 1}) {
		t.Fatalf("binding %v", members.data)
	}
}

func TestRejectsWrongBindingLayoutAndPolicyErrors(t *testing.T) {
	b, policy, members, log := newFixture(t, func(Map) error { return nil })
	members.max = 8
	if err := b.start(policy, members, nil, nil); err == nil || len(*log) != 0 {
		t.Fatalf("wrong binding layout must fail before writes: %v %v", err, *log)
	}
	b, policy, members, log = newFixture(t, func(Map) error { return errors.New("bad layout") })
	if err := b.start(policy, members, nil, nil); err == nil || len(*log) != 0 {
		t.Fatalf("policy writer error must stop startup: %v %v", err, *log)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{Name: "x", PolicyMap: "p", WritePolicy: func(Map) error { return nil }}); err == nil {
		t.Fatal("zero generation must fail")
	}
}

func TestStartSkipsGoneContainer(t *testing.T) {
	b, policy, members, _ := newFixture(t, func(Map) error { return nil })
	b.armExisting = func(Map, string) error { return ErrContainerGone }
	if err := b.start(policy, members, &fakeMap{typ: ebpf.TaskStorage}, nil); err != nil {
		t.Fatalf("a gone container must not fail startup: %v", err)
	}
	if err := b.Ready(nil); err != nil || len(members.data) != 0 {
		t.Fatalf("ready=%v bindings=%v", err, members.data)
	}
	// A failed live call does not make the instance unready.
	if err := b.Bind(Binding{Container: identity}); err == nil {
		t.Fatal("bind of a gone container must report it")
	}
	if st := b.Status(); !st.Ready || st.Error != nil || st.LastError == nil {
		t.Fatalf("status %+v", st)
	}
}

type fakeFaults map[uint32]uint64

func (f fakeFaults) Lookup(k, v interface{}) error {
	*v.(*uint64) = f[k.(uint32)]
	return nil
}
func (fakeFaults) Type() ebpf.MapType { return ebpf.Array }
func (fakeFaults) KeySize() uint32    { return 4 }
func (fakeFaults) ValueSize() uint32  { return 8 }
func (fakeFaults) MaxEntries() uint32 { return 64 }

func TestSlotFaults(t *testing.T) {
	b, policy, members, _ := newFixture(t, func(Map) error { return nil })
	if _, err := b.SlotFaults(0); err == nil {
		t.Fatal("no fault map must be an error, not zero faults")
	}
	if err := b.start(policy, members, nil, fakeFaults{1: 3}); err != nil {
		t.Fatal(err)
	}
	if n, err := b.SlotFaults(0); err != nil || n != 0 {
		t.Fatalf("slot 0: %d %v", n, err)
	}
	if n, err := b.SlotFaults(1); err != nil || n != 3 {
		t.Fatalf("slot 1: %d %v", n, err)
	}
}
