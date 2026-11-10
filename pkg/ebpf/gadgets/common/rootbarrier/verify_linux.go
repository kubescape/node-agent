// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Verify attests the barrier of a started gadget instance and runs the
// self-test. Call it from the Ready step of the gadget's operator, with Hooks
// or a copy from WithProgram.
func Verify(gc operators.GadgetContext, hooks []Hook) error {
	counters, err := instanceMap(gc, CountersMap)
	if err != nil {
		return err
	}
	probe, err := instanceMap(gc, ProbeMap)
	if err != nil {
		return err
	}
	return VerifyMaps(counters, probe, hooks)
}

// VerifyMaps is Verify for the maps of an instance, for example maps opened
// from pins when a gadget adopts a long-lived instance after a restart. It
// first clears the probe entry, which a previous owner can have left, then
// attests the links and runs the self-test. Until it passes, the gadget must
// not report Strict enforcement as Ready.
func VerifyMaps(counters, probe *ebpf.Map, hooks []Hook) error {
	if err := ClearProbe(probe); err != nil {
		return err
	}
	if err := Attest(counters, hooks); err != nil {
		return err
	}
	return SelfTest(probe)
}

func instanceMap(gc operators.GadgetContext, name string) (*ebpf.Map, error) {
	value, _ := gc.GetVar(operators.MapPrefix + name)
	m, ok := value.(*ebpf.Map)
	if !ok || m == nil {
		return nil, fmt.Errorf("root barrier: missing BPF map %s", name)
	}
	return m, nil
}
