// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package rootbarrier proves that the root barrier of ../root_barrier.h works
// in a running gadget instance, before the instance reports Ready: every
// barrier program has a live LSM link, BPF LSM is active, and a self-test sees
// the barrier deny real operations. A gadget that includes the barrier calls
// Verify from its Ready step; an error must refuse activation.
package rootbarrier

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

// Map names in ../root_barrier.h.
const (
	CountersMap = "root_barrier_counters"
	ProbeMap    = "root_barrier_probe"
)

// Op is enum root_barrier_op in ../root_barrier.h: a counter slot.
type Op uint32

const (
	OpChroot Op = iota
	OpPivotRoot
	OpUserns
	OpCloneNS
	OpUnshareNS
	OpSetns
	OpMount
	OpMoveMount
	OpUmount
	OpNewMount
	OpCompat
	opMax
)

var opNames = [opMax]string{"chroot", "pivot_root", "userns", "clone_ns", "unshare_ns", "setns", "mount", "move_mount", "umount", "new_mount", "compat"}

func (o Op) String() string {
	if o < opMax {
		return opNames[o]
	}
	return fmt.Sprintf("op(%d)", uint32(o))
}

// Hook is one barrier program and the LSM hook it must be attached to.
type Hook struct {
	Program string
	LSM     string
}

// Hooks lists every program of ../root_barrier.h.
var Hooks = []Hook{
	{"rb_chroot", "path_chroot"},
	{"rb_pivotroot", "sb_pivotroot"},
	{"rb_userns", "userns_create"},
	{"rb_task_alloc", "task_alloc"},
	{"rb_capable", "capable"},
	{"rb_sb_mount", "sb_mount"},
	{"rb_move_mount", "move_mount"},
	{"rb_sb_umount", "sb_umount"},
}

// Denials returns the denial count of each operation, summed over CPUs.
func Denials(counters *ebpf.Map) (map[Op]uint64, error) {
	result := map[Op]uint64{}
	for op := Op(0); op < opMax; op++ {
		n, err := denials(counters, op)
		if err != nil {
			return nil, err
		}
		result[op] = n
	}
	return result, nil
}

func denials(counters *ebpf.Map, op Op) (uint64, error) {
	var perCPU []uint64
	if err := counters.Lookup(uint32(op), &perCPU); err != nil {
		return 0, fmt.Errorf("root barrier: reading %s counter: %w", op, err)
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

func lsmListHasBPF(list string) bool {
	return slices.Contains(strings.Split(strings.TrimSpace(list), ","), "bpf")
}
