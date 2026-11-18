// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestSwitches are the fault-injection constants of ../arming.h. A section
// adds its own (Config.TestSwitches). They exist only for the kernel tests: a
// production instance must never run with one set.
var TestSwitches = []string{"arming_fail_fork_marks", "arming_fail_exec_marks"}

// rodata is the map of the program's constants (const volatile).
const rodata = ".rodata"

// ForceTestSwitchesOff sets the test switches (TestSwitches plus extra) to 0
// as native constants. The eBPF operator applies them after the gadget
// parameters and before the load, so an instance that does not admit fault
// injection never loads with a switch set, whatever its parameters say.
// checkTestSwitches stays as a backstop. Call it from the data operator's
// InstantiateDataOperator, before the eBPF operator starts.
func ForceTestSwitchesOff(gc operators.GadgetContext, extra []string) error {
	constants := map[string]any{}
	if value, ok := gc.GetVar(operators.NativeConstantsKey); ok {
		switch typed := value.(type) {
		case map[string]any:
			for k, v := range typed {
				constants[k] = v
			}
		case map[string]uint32:
			for k, v := range typed {
				constants[k] = v
			}
		case map[string]uint64:
			for k, v := range typed {
				constants[k] = v
			}
		default:
			return fmt.Errorf("unexpected native constants %T", value)
		}
	}
	for _, name := range append(append([]string{}, TestSwitches...), extra...) {
		constants[name] = uint32(0)
	}
	gc.SetVar(operators.NativeConstantsKey, constants)
	return nil
}

// checkTestSwitches refuses an instance whose loaded program has a test
// switch set (gadget parameters can set them), unless Config.FaultInjection
// admits fault injection. It reads the loaded constants, not the parameters.
func (b *Bindings) checkTestSwitches(gc operators.GadgetContext) error {
	if b.config.FaultInjection {
		return nil
	}
	names := append(append([]string{}, TestSwitches...), b.config.TestSwitches...)
	specValue, _ := gc.GetVar(operators.MapSpecPrefix + rodata)
	spec, _ := specValue.(*ebpf.MapSpec)
	if spec == nil {
		// No constants at all (const volatile goes to .rodata): no test
		// switch can be set.
		return nil
	}
	mapValue, _ := gc.GetVar(operators.MapPrefix + rodata)
	m, _ := mapValue.(*ebpf.Map)
	if m == nil {
		return fmt.Errorf("cannot check the test switches: no %s map", rodata)
	}
	data := make([]byte, m.ValueSize())
	if err := m.Lookup(uint32(0), data); err != nil {
		return fmt.Errorf("cannot check the test switches: reading %s: %w", rodata, err)
	}
	set, err := switchesSet(spec, data, names)
	if err != nil {
		return err
	}
	if len(set) > 0 {
		return fmt.Errorf("%s: test-only switches set %v; refused outside the kernel tests", b.config.Name, set)
	}
	return nil
}

// switchesSet returns the names whose constant in data (the .rodata value)
// is nonzero. A name that the program does not have is not set.
func switchesSet(spec *ebpf.MapSpec, data []byte, names []string) ([]string, error) {
	sec, ok := spec.Value.(*btf.Datasec)
	if !ok {
		return nil, fmt.Errorf("cannot check the test switches: %s has no BTF section", rodata)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var set []string
	for _, v := range sec.Vars {
		vv, ok := v.Type.(*btf.Var)
		if !ok || !want[vv.Name] {
			continue
		}
		end := v.Offset + v.Size
		if int(end) > len(data) {
			return nil, fmt.Errorf("cannot check the test switches: %s outside %s", vv.Name, rodata)
		}
		for _, c := range data[v.Offset:end] {
			if c != 0 {
				set = append(set, vv.Name)
				break
			}
		}
	}
	sort.Strings(set)
	return set, nil
}
