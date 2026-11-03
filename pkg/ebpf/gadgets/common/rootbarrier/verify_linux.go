// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Verify attests the barrier of a started gadget instance and runs the
// self-test. Call it from the Ready step of the gadget's operator.
func Verify(gc operators.GadgetContext) error {
	counters, err := instanceMap(gc, CountersMap)
	if err != nil {
		return err
	}
	probe, err := instanceMap(gc, ProbeMap)
	if err != nil {
		return err
	}
	if err := Attest(counters); err != nil {
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
