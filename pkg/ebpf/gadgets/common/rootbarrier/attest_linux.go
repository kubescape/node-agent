// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// Attest proves that each barrier program of the instance that owns counters
// has a live LSM link to its hook, and that the kernel runs BPF LSM programs.
// A program belongs to the instance when it uses the instance's counter map.
func Attest(counters *ebpf.Map) error {
	if err := bpfLSMActive(); err != nil {
		return err
	}
	info, err := counters.Info()
	if err != nil {
		return fmt.Errorf("root barrier: counter map info: %w", err)
	}
	mapID, ok := info.ID()
	if !ok {
		return fmt.Errorf("root barrier: counter map ID unavailable")
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("root barrier: kernel BTF: %w", err)
	}
	attached, err := attachedHooks(mapID, kernel)
	if err != nil {
		return err
	}
	var missing []string
	for _, h := range Hooks {
		if !attached[h] {
			missing = append(missing, h.Program+"->"+h.LSM)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("root barrier: no live LSM link for %s", strings.Join(missing, ", "))
	}
	return nil
}

// attachedHooks walks every BPF link of the kernel and returns the barrier
// hooks with a live LSM link to a program that uses the map mapID.
func attachedHooks(mapID ebpf.MapID, kernel *btf.Spec) (map[Hook]bool, error) {
	attached := map[Hook]bool{}
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
		hook, ok, err := barrierHook(info.Program, mapID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		target, err := kernel.TypeByID(btf.TypeID(tracing.TargetBtfId))
		if err != nil || target.TypeName() != "bpf_lsm_"+hook.LSM {
			continue
		}
		attached[hook] = true
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("root barrier: listing BPF links: %w", err)
	}
	return attached, nil
}

// barrierHook returns the barrier hook of the program id when it is a barrier
// program of the instance that owns mapID.
func barrierHook(id ebpf.ProgramID, mapID ebpf.MapID) (Hook, bool, error) {
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
	i := slices.IndexFunc(Hooks, func(h Hook) bool { return h.Program == info.Name })
	if i < 0 {
		return Hook{}, false, nil
	}
	maps, ok := info.MapIDs()
	if !ok || !slices.Contains(maps, mapID) {
		return Hook{}, false, nil
	}
	return Hooks[i], true, nil
}

// bpfLSMActive checks the kernel's active LSM list. A BPF LSM program attaches
// even when "bpf" is not in that list, and then never runs.
func bpfLSMActive() error {
	var data []byte
	var err error
	for _, path := range []string{filepath.Join(host.HostRoot, "sys/kernel/security/lsm"), "/sys/kernel/security/lsm"} {
		if data, err = os.ReadFile(path); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("root barrier: reading the active LSM list: %w", err)
	}
	if !lsmListHasBPF(string(data)) {
		return fmt.Errorf("root barrier: BPF LSM is not active (lsm list %q)", strings.TrimSpace(string(data)))
	}
	return nil
}
