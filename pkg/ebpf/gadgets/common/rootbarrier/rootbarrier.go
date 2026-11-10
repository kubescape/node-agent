// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package rootbarrier proves that the root barrier of ../root_barrier.h works
// in a running gadget instance, before the instance reports Ready: every
// barrier program has a live LSM link, BPF LSM is active, and a self-test sees
// the barrier deny real operations. A gadget that includes the barrier calls
// Verify from its Ready step; an error must refuse activation. A gadget that
// adopts a running instance after a restart (for example pinned links of a
// long-lived collection) calls VerifyMaps again before it reports Strict
// enforcement as Ready.
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
	FaultsMap   = "root_barrier_faults"
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

// Fault is enum root_barrier_fault in ../root_barrier.h: a fault counter
// slot.
type Fault uint32

const (
	// FaultDenied counts predicate faults under a Strict class (denied).
	FaultDenied Fault = iota
	// FaultAllowed counts predicate faults under an Audit class (allowed).
	FaultAllowed
	faultMax
)

// probeEntry matches struct root_barrier_probe in ../root_barrier.h.
type probeEntry struct {
	Tid      uint32
	Denied   uint32
	PidnsDev uint64
	PidnsIno uint64
	Nonce    [16]byte // ROOT_BARRIER_NONCE_LEN
}

// Hook is one barrier program and the LSM hook it must be attached to. Args
// is the hook's argument count: the program reads the previous BPF verdict
// (`ret`) right after them, so the count must match the running kernel.
type Hook struct {
	Program string
	LSM     string
	Args    int
}

// Hooks lists every program of ../root_barrier.h. A gadget that carries a
// hook body in its own program (ROOT_BARRIER_NO_<NAME>_PROGRAM) passes a copy
// with that program's name to Attest, for example WithProgram(Hooks,
// "task_alloc", "my_task_alloc").
var Hooks = []Hook{
	{"rb_chroot", "path_chroot", 1},
	{"rb_pivotroot", "sb_pivotroot", 2},
	{"rb_userns", "userns_create", 1},
	{"rb_task_alloc", "task_alloc", 2},
	{"rb_capable", "capable", 4},
	{"rb_sb_mount", "sb_mount", 5},
	{"rb_move_mount", "move_mount", 2},
	{"rb_sb_umount", "sb_umount", 2},
}

// WithProgram returns a copy of hooks in which the program of the LSM hook is
// program.
func WithProgram(hooks []Hook, lsm, program string) []Hook {
	result := slices.Clone(hooks)
	for i := range result {
		if result[i].LSM == lsm {
			result[i].Program = program
		}
	}
	return result
}

// checkHooks refuses a hook list that does not name one program for each hook
// of ../root_barrier.h, with the header's argument count.
func checkHooks(hooks []Hook) error {
	if len(hooks) != len(Hooks) {
		return fmt.Errorf("root barrier: %d hooks, want %d", len(hooks), len(Hooks))
	}
	programs := map[string]bool{}
	for _, want := range Hooks {
		i := slices.IndexFunc(hooks, func(h Hook) bool { return h.LSM == want.LSM })
		if i < 0 {
			return fmt.Errorf("root barrier: no program for hook %s", want.LSM)
		}
		h := hooks[i]
		if h.Args != want.Args {
			return fmt.Errorf("root barrier: hook %s has %d arguments, want %d", h.LSM, h.Args, want.Args)
		}
		// The kernel keeps 15 characters of a program name.
		if h.Program == "" || len(h.Program) > 15 || programs[h.Program] {
			return fmt.Errorf("root barrier: invalid or repeated program name %q for hook %s", h.Program, h.LSM)
		}
		programs[h.Program] = true
	}
	return nil
}

// Denials returns the denial count of each operation, summed over CPUs.
func Denials(counters *ebpf.Map) (map[Op]uint64, error) {
	result := map[Op]uint64{}
	for op := Op(0); op < opMax; op++ {
		n, err := sumSlot(counters, uint32(op))
		if err != nil {
			return nil, fmt.Errorf("root barrier: reading %s counter: %w", op, err)
		}
		result[op] = n
	}
	return result, nil
}

// Faults returns the predicate fault counts of the faults map, summed over
// CPUs. A gadget reads them for its Ready or degraded status: a nonzero
// count means the predicate could not decide for some task.
func Faults(faults *ebpf.Map) (map[Fault]uint64, error) {
	result := map[Fault]uint64{}
	for f := Fault(0); f < faultMax; f++ {
		n, err := sumSlot(faults, uint32(f))
		if err != nil {
			return nil, fmt.Errorf("root barrier: reading fault counter %d: %w", f, err)
		}
		result[f] = n
	}
	return result, nil
}

func sumSlot(m *ebpf.Map, key uint32) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0, err
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
