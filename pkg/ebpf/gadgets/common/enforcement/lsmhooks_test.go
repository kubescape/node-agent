// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// kernelWith builds a synthetic kernel BTF with bpf_lsm_<hook> taking n
// pointer arguments.
func kernelWith(t *testing.T, hooks map[string]int) *btf.Spec {
	t.Helper()
	b, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ptr := &btf.Pointer{Target: &btf.Void{}}
	for hook, n := range hooks {
		proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
		for i := 0; i < n; i++ {
			proto.Params = append(proto.Params, btf.FuncParam{Name: "a", Type: ptr})
		}
		if _, err := b.Add(&btf.Func{Name: "bpf_lsm_" + hook, Type: proto, Linkage: btf.GlobalFunc}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return kernel
}

func TestLSMHookArgMismatches(t *testing.T) {
	// Before and from Linux 6.15: bpf has 3 then 4 arguments, perf_event_open 2 then 1.
	accepted := map[string][]int{"bpf": {3, 4}, "perf_event_open": {2, 1}, "path_chroot": {1}}
	for name, kernel := range map[string]map[string]int{
		"6.14": {"bpf": 3, "perf_event_open": 2, "path_chroot": 1},
		"6.15": {"bpf": 4, "perf_event_open": 1, "path_chroot": 1},
	} {
		if bad := LSMHookArgMismatches(kernelWith(t, kernel), accepted); len(bad) != 0 {
			t.Errorf("%s: %v", name, bad)
		}
	}
	// One unknown signature and one missing hook: only those two are reported.
	bad := LSMHookArgMismatches(kernelWith(t, map[string]int{"bpf": 5, "perf_event_open": 2}), accepted)
	if len(bad) != 2 || bad["bpf"] == nil || bad["path_chroot"] == nil || bad["perf_event_open"] != nil {
		t.Fatalf("per-hook result: %v", bad)
	}
}

func TestCheckLSMHookArgs(t *testing.T) {
	kernel := kernelWith(t, map[string]int{"two": 2})
	if err := CheckLSMHookArgs(kernel, map[string]int{"two": 2}); err != nil {
		t.Fatalf("matching count: %v", err)
	}
	if CheckLSMHookArgs(kernel, map[string]int{"two": 3}) == nil {
		t.Fatal("another argument count must be refused")
	}
	if CheckLSMHookArgs(kernel, map[string]int{"missing": 1}) == nil {
		t.Fatal("a missing hook must be refused")
	}
}
