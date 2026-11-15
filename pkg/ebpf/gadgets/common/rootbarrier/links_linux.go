// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Readiness by link ID. Attest finds the barrier programs by name and by the
// instance's counter map. A gadget that reports its status more often than it
// verifies reads the program IDs once (ProgramIDs, after a verification
// passed) and then checks on each status read that every one of them still
// has a live LSM link to its hook (CheckLinks). A detached link then never
// leaves a stale healthy status.

// ProgramIDs returns the ID of the program of each hook of hooks that uses
// the counter map of the instance. It walks the programs of the kernel, not
// the links, so a program with no link is found too. A hook with no program,
// or with more than one, is an error.
func ProgramIDs(counters *ebpf.Map, hooks []Hook) (map[Hook]ebpf.ProgramID, error) {
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
	ids := map[Hook]ebpf.ProgramID{}
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("root barrier: listing BPF programs: %w", err)
		}
		id = next
		hook, ok, err := programHook(id, mapID, hooks)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if prev, dup := ids[hook]; dup {
			return nil, fmt.Errorf("root barrier: programs %d and %d both carry %s", prev, id, hook.Program)
		}
		ids[hook] = id
	}
	var missing []string
	for _, h := range hooks {
		if _, ok := ids[h]; !ok {
			missing = append(missing, h.Program+"->"+h.LSM)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("root barrier: no loaded program for %s", strings.Join(missing, ", "))
	}
	return ids, nil
}

// programHook returns the hook of the program id when its name is the
// program of that hook and it uses the map mapID.
func programHook(id ebpf.ProgramID, mapID ebpf.MapID, hooks []Hook) (Hook, bool, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if errors.Is(err, os.ErrNotExist) {
		return Hook{}, false, nil
	}
	if err != nil {
		return Hook{}, false, fmt.Errorf("root barrier: opening program %d: %w", id, err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		return Hook{}, false, fmt.Errorf("root barrier: program %d info: %w", id, err)
	}
	i := slices.IndexFunc(hooks, func(h Hook) bool { return h.Program == info.Name })
	if i < 0 {
		return Hook{}, false, nil
	}
	maps, ok := info.MapIDs()
	if !ok || !slices.Contains(maps, mapID) {
		return Hook{}, false, nil
	}
	return hooks[i], true, nil
}

// CheckLinks checks that each program of ids has a live LSM link to its hook:
// a link of the program with that ID, not only of a program with that name.
// A missing link is an error that names the program and its hook.
func CheckLinks(ids map[Hook]ebpf.ProgramID) error {
	if len(ids) == 0 {
		return fmt.Errorf("root barrier: no program IDs to check")
	}
	var linked map[ebpf.ProgramID]map[string]bool
	var err error
	for attempt := 0; ; attempt++ {
		linked, err = walkLinks()
		if err == nil || !errors.Is(err, unix.EAGAIN) || attempt == walkRetries {
			break
		}
		time.Sleep(walkRetryDelay)
	}
	if err != nil {
		return err
	}
	var missing []string
	for h, id := range ids {
		if !linked[id]["bpf_lsm_"+h.LSM] {
			missing = append(missing, fmt.Sprintf("%s->%s (program %d)", h.Program, h.LSM, id))
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("root barrier: no live LSM link for %s", strings.Join(missing, ", "))
	}
	return nil
}

// walkLinks is one walk (replaced in tests).
var walkLinks = walkLSMLinks

// walkLSMLinks returns, for each program with a live LSM link, the BTF names
// of the targets of its links (bpf_lsm_<hook>).
func walkLSMLinks() (map[ebpf.ProgramID]map[string]bool, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("root barrier: kernel BTF: %w", err)
	}
	linked := map[ebpf.ProgramID]map[string]bool{}
	var it link.Iterator
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil || info.Type != link.TracingType {
			continue
		}
		tracing := info.Tracing()
		if tracing == nil || ebpf.AttachType(tracing.AttachType) != ebpf.AttachLSMMac {
			continue
		}
		target, err := kernel.TypeByID(btf.TypeID(tracing.TargetBtfId))
		if err != nil {
			continue
		}
		if linked[info.Program] == nil {
			linked[info.Program] = map[string]bool{}
		}
		linked[info.Program][target.TypeName()] = true
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("root barrier: listing BPF links: %w", err)
	}
	return linked, nil
}
