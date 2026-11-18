// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func rodataSpec() *ebpf.MapSpec {
	u64 := &btf.Int{Name: "u64", Size: 8}
	b := &btf.Int{Name: "bool", Size: 1, Encoding: btf.Bool}
	return &ebpf.MapSpec{Name: rodata, Value: &btf.Datasec{Name: rodata, Vars: []btf.VarSecinfo{
		{Type: &btf.Var{Name: "host_mntns_id", Type: u64}, Offset: 0, Size: 8},
		{Type: &btf.Var{Name: "arming_fail_fork_marks", Type: b}, Offset: 8, Size: 1},
		{Type: &btf.Var{Name: "policy_fail_headers", Type: b}, Offset: 9, Size: 1},
	}}}
}

func TestSwitchesSet(t *testing.T) {
	names := []string{"arming_fail_fork_marks", "arming_fail_exec_marks", "policy_fail_headers"}
	data := make([]byte, 10)
	data[0] = 7 // host_mntns_id is not a test switch
	set, err := switchesSet(rodataSpec(), data, names)
	if err != nil || len(set) != 0 {
		t.Fatalf("production constants: %v %v", set, err)
	}
	data[8], data[9] = 1, 1
	set, err = switchesSet(rodataSpec(), data, names)
	if err != nil || !slices.Equal(set, []string{"arming_fail_fork_marks", "policy_fail_headers"}) {
		t.Fatalf("switches set: %v %v", set, err)
	}
	if _, err := switchesSet(rodataSpec(), make([]byte, 9), names); err == nil {
		t.Fatal("a switch outside the data must be an error, not unset")
	}
	if _, err := switchesSet(&ebpf.MapSpec{Name: rodata}, data, names); err == nil {
		t.Fatal("no BTF section must be an error, not unset")
	}
}

func TestFaultInjectionAdmitsSwitches(t *testing.T) {
	b, err := New(Config{Name: "test", Generation: 1, Slots: 1, PolicyMap: "p", WritePolicy: func(Map) error { return nil }, FaultInjection: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.checkTestSwitches(nil); err != nil {
		t.Fatalf("FaultInjection admits without reading the program: %v", err)
	}
}

// fakeVars is a gadget context with only its variables.
type fakeVars struct {
	operators.GadgetContext
	vars map[string]any
}

func (f *fakeVars) GetVar(name string) (any, bool) { v, ok := f.vars[name]; return v, ok }
func (f *fakeVars) SetVar(name string, v any)      { f.vars[name] = v }

func TestForceTestSwitchesOff(t *testing.T) {
	gc := &fakeVars{vars: map[string]any{operators.NativeConstantsKey: map[string]uint32{"other": 7}}}
	if err := ForceTestSwitchesOff(gc, []string{"policy_fail_headers"}); err != nil {
		t.Fatal(err)
	}
	got, _ := gc.vars[operators.NativeConstantsKey].(map[string]any)
	for _, name := range []string{"arming_fail_fork_marks", "arming_fail_exec_marks", "policy_fail_headers"} {
		if v, ok := got[name].(uint32); !ok || v != 0 {
			t.Fatalf("%s must be forced to 0: %v", name, got)
		}
	}
	if got["other"] != uint32(7) {
		t.Fatalf("other native constants stay: %v", got)
	}
	bad := &fakeVars{vars: map[string]any{operators.NativeConstantsKey: "x"}}
	if err := ForceTestSwitchesOff(bad, nil); err == nil {
		t.Fatal("an unexpected constants type is an error")
	}
}
