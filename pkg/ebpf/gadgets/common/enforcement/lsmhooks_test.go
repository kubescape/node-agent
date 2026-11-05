// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestCheckLSMHookArgs(t *testing.T) {
	b, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ptr := &btf.Pointer{Target: &btf.Void{}}
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{{Name: "a", Type: ptr}, {Name: "b", Type: ptr}}}
	if _, err := b.Add(&btf.Func{Name: "bpf_lsm_two", Type: proto, Linkage: btf.GlobalFunc}); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
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
