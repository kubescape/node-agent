// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
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

func TestFtraceEnabled(t *testing.T) {
	for value, want := range map[string]bool{
		"1\n": true,
		"1":   true,
		"0\n": false,
		"":    false,
		"10":  false,
	} {
		if got := ftraceEnabled(value); got != want {
			t.Errorf("%q: got %v, want %v", value, got, want)
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
	programs := regexp.MustCompile(`#ifndef ROOT_BARRIER_NO_(\w+)_PROGRAM\nSEC\("lsm/(\w+)"\)\s*\nlong BPF_PROG\((\w+),([^)]*)\)\s*\{\s*__s64 prior = ROOT_BARRIER_PRIOR\((\d+)\);`).FindAllStringSubmatch(header, -1)
	if len(programs) != len(Hooks) {
		t.Fatalf("header has %d programs, Hooks has %d", len(programs), len(Hooks))
	}
	for i, m := range programs {
		guard, lsm, program, params, prior := m[1], m[2], m[3], m[4], m[5]
		// Each program has its own opt-out, named after the program.
		if want := strings.ToUpper(strings.TrimPrefix(program, "rb_")); guard != want {
			t.Errorf("program %s: opt-out ROOT_BARRIER_NO_%s_PROGRAM, want ROOT_BARRIER_NO_%s_PROGRAM", program, guard, want)
		}
		// The arguments end with the previous verdict, `int ret`.
		args := strings.Count(params, ",")
		if !strings.HasSuffix(strings.TrimSpace(params), "int ret") {
			t.Errorf("program %s does not end with int ret", program)
		}
		// The program reads the previous verdict at that position.
		if prior != strconv.Itoa(args) {
			t.Errorf("program %s reads the previous verdict at %s, want %d", program, prior, args)
		}
		if Hooks[i] != (Hook{Program: program, LSM: lsm, Args: args}) {
			t.Errorf("program %d: header %s->%s, Hooks %v", i, program, lsm, Hooks[i])
		}
	}
	if err := checkHooks(Hooks); err != nil {
		t.Errorf("Hooks: %v", err)
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
	faultEnum := regexp.MustCompile(`(?s)enum root_barrier_fault : __u32 \{(.*?)\};`).FindStringSubmatch(header)
	if faultEnum == nil {
		t.Fatal("enum root_barrier_fault not found")
	}
	faults := regexp.MustCompile(`ROOT_BARRIER_FAULT_(\w+) = (\d+),`).FindAllStringSubmatch(faultEnum[1], -1)
	want := []string{"DENIED", "ALLOWED", "MAX"}
	if len(faults) != len(want) || int(faultMax) != len(want)-1 {
		t.Fatalf("header has %d fault values, want %d", len(faults), len(want))
	}
	for i, m := range faults {
		if m[1] != want[i] || m[2] != strconv.Itoa(i) {
			t.Errorf("fault %d: header %s = %s, want %s = %d", i, m[1], m[2], want[i], i)
		}
	}
}

// probeEntry has the layout of struct root_barrier_probe: u32, u32, u64,
// u64 and the nonce, with no padding.
func TestProbeEntryMatchesHeader(t *testing.T) {
	data, err := os.ReadFile("../root_barrier.h")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`#define ROOT_BARRIER_NONCE_LEN (\d+)`).FindStringSubmatch(string(data))
	if m == nil || m[1] != strconv.Itoa(len(probeEntry{}.Nonce)) {
		t.Fatalf("ROOT_BARRIER_NONCE_LEN %v, Go nonce %d bytes", m, len(probeEntry{}.Nonce))
	}
	if !regexp.MustCompile(`(?s)struct root_barrier_probe \{\s*//[^\n]*\n\s*__u32 tid;.*?__u32 denied;.*?__u64 pidns_dev;\s*__u64 pidns_ino;.*?char nonce\[ROOT_BARRIER_NONCE_LEN\];\s*\};`).MatchString(string(data)) {
		t.Fatal("struct root_barrier_probe changed: update probeEntry")
	}
	if size := unsafe.Sizeof(probeEntry{}); size != 40 {
		t.Fatalf("probeEntry is %d bytes, want 40", size)
	}
}

// An includer can carry a hook body in its own program; any other change to
// the hook list is refused.
func TestCheckHooks(t *testing.T) {
	inline := WithProgram(Hooks, "task_alloc", "eo_task_alloc")
	if err := checkHooks(inline); err != nil {
		t.Fatalf("own task_alloc program: %v", err)
	}
	if inline[3].Program != "eo_task_alloc" || Hooks[3].Program != "rb_task_alloc" {
		t.Fatalf("WithProgram: got %v, Hooks %v", inline[3], Hooks[3])
	}
	// A program matched by its ID can have a long or shared name.
	if err := checkHooks(withID(Hooks, "task_alloc", "opaque_real_own", 7)); err != nil {
		t.Fatalf("program matched by ID: %v", err)
	}
	if err := checkHooks(withID(Hooks, "task_alloc", "rb_chroot", 7)); err != nil {
		t.Fatalf("program matched by ID, name of another hook: %v", err)
	}
	for name, hooks := range map[string][]Hook{
		"missing hook":    Hooks[1:],
		"extra hook":      append(slices.Clone(Hooks), Hook{Program: "rb_extra", LSM: "file_open", Args: 1}),
		"repeated hook":   append(slices.Clone(Hooks[1:]), Hooks[1]),
		"other arguments": func() []Hook { h := slices.Clone(Hooks); h[0].Args = 2; return h }(),
		"long name":       WithProgram(Hooks, "capable", "a_long_program_name"),
		"empty name":      WithProgram(Hooks, "capable", ""),
		"repeated name":   WithProgram(Hooks, "capable", "rb_chroot"),
		"repeated ID":     withID(withID(Hooks, "capable", "c", 7), "sb_mount", "m", 7),
	} {
		if err := checkHooks(hooks); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// withID is WithProgramID without a loaded program.
func withID(hooks []Hook, lsm, name string, id ebpf.ProgramID) []Hook {
	result := WithProgram(hooks, lsm, name)
	for i := range result {
		if result[i].LSM == lsm {
			result[i].ID = id
		}
	}
	return result
}
