// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestLSMListHasBPF(t *testing.T) {
	for list, want := range map[string]bool{
		"lockdown,capability,landlock,yama,apparmor,bpf\n": true,
		"bpf":                        true,
		"capability,apparmor":        false,
		"capability,bpfx,apparmor\n": false,
		"":                           false,
	} {
		if got := lsmListHasBPF(list); got != want {
			t.Errorf("%q: got %v, want %v", list, got, want)
		}
	}
}

// The Go lists must match ../root_barrier.h.
func TestHooksMatchHeader(t *testing.T) {
	data, err := os.ReadFile("../root_barrier.h")
	if err != nil {
		t.Fatal(err)
	}
	header := string(data)
	programs := regexp.MustCompile(`SEC\("lsm/(\w+)"\)\s*\nint BPF_PROG\((\w+)`).FindAllStringSubmatch(header, -1)
	if len(programs) != len(Hooks) {
		t.Fatalf("header has %d programs, Hooks has %d", len(programs), len(Hooks))
	}
	for i, m := range programs {
		if Hooks[i] != (Hook{Program: m[2], LSM: m[1]}) {
			t.Errorf("program %d: header %s->%s, Hooks %v", i, m[2], m[1], Hooks[i])
		}
		if len(m[2]) > 15 {
			t.Errorf("program name %s is longer than the kernel keeps", m[2])
		}
	}
	opEnum := regexp.MustCompile(`(?s)enum root_barrier_op : __u32 \{(.*?)\};`).FindStringSubmatch(header)
	if opEnum == nil {
		t.Fatal("enum root_barrier_op not found")
	}
	ops := regexp.MustCompile(`ROOT_BARRIER_(\w+) = (\d+),`).FindAllStringSubmatch(opEnum[1], -1)
	if len(ops) != int(opMax)+1 {
		t.Fatalf("header has %d op values, want %d", len(ops), opMax+1)
	}
	for i, m := range ops[:opMax] {
		if m[2] != strconv.Itoa(i) || !strings.EqualFold(strings.ReplaceAll(m[1], "_", ""), strings.ReplaceAll(Op(i).String(), "_", "")) {
			t.Errorf("op %d: header %s = %s, Go %s", i, m[1], m[2], Op(i))
		}
	}
}
