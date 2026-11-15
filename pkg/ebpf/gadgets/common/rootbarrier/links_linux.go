// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

// Readiness by program ID. Attest matches a hook's program by its kernel ID when
// the hook has one (Hook.ID, WithProgramID). WithProgramID needs the loaded
// *ebpf.Program; a gadget that only has the instance's maps (for example the
// standalone root_barrier gadget, whose LSM programs Inspektor Gadget does not
// expose) reads the IDs with ProgramIDs once, after a verification passed,
// and then runs Attest with the returned hooks on each status read. A
// detached link then never leaves a stale healthy status, and a newer program
// with the same name does not count.

// ProgramIDs returns a copy of hooks in which each hook carries the kernel ID
// of its program: the program with the hook's name that uses the counter map
// of the instance. It walks the programs of the kernel, not the links, so a
// program with no link is found too. A hook that already has an ID keeps it.
// A hook with no program, or with more than one, is an error.
func ProgramIDs(counters *ebpf.Map, hooks []Hook) ([]Hook, error) {
	if err := checkHooks(hooks); err != nil {
		return nil, err
	}
	info, err := counters.Info()
	if err != nil {
		return nil, fmt.Errorf("root barrier: counter map info: %w", err)
	}
	mapID, ok := info.ID()
	if !ok {
		return nil, fmt.Errorf("root barrier: counter map ID unavailable")
	}
	return programIDs(mapID, hooks)
}

func programIDs(mapID ebpf.MapID, hooks []Hook) ([]Hook, error) {
	found, err := walkPrograms(mapID, hooks)
	if err != nil {
		return nil, err
	}
	result := slices.Clone(hooks)
	var missing []string
	for i, h := range result {
		if h.ID != 0 {
			continue
		}
		switch ids := found[h.Program]; len(ids) {
		case 0:
			missing = append(missing, h.Program+"->"+h.LSM)
		case 1:
			result[i].ID = ids[0]
		default:
			return nil, fmt.Errorf("root barrier: programs %v all carry %s", ids, h.Program)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("root barrier: no loaded program for %s", strings.Join(missing, ", "))
	}
	return result, nil
}

// walkPrograms is one walk (replaced in tests).
var walkPrograms = walkBarrierPrograms

// walkBarrierPrograms returns, by program name, the IDs of the programs named
// in hooks that use the map mapID.
func walkBarrierPrograms(mapID ebpf.MapID, hooks []Hook) (map[string][]ebpf.ProgramID, error) {
	found := map[string][]ebpf.ProgramID{}
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			return found, nil
		}
		if err != nil {
			return nil, fmt.Errorf("root barrier: listing BPF programs: %w", err)
		}
		id = next
		prog, err := ebpf.NewProgramFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("root barrier: opening program %d: %w", id, err)
		}
		info, err := prog.Info()
		prog.Close()
		if err != nil {
			return nil, fmt.Errorf("root barrier: program %d info: %w", id, err)
		}
		if !slices.ContainsFunc(hooks, func(h Hook) bool { return h.ID == 0 && h.Program == info.Name }) {
			continue
		}
		maps, ok := info.MapIDs()
		if !ok {
			return nil, fmt.Errorf("root barrier: map IDs of program %d unavailable", id)
		}
		if slices.Contains(maps, mapID) {
			found[info.Name] = append(found[info.Name], id)
		}
	}
}
