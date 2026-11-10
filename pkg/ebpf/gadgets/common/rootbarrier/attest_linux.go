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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// Attest proves that each program of hooks (Hooks, or a copy from
// WithProgram) of the instance that owns counters has a live LSM link to its
// hook, and that the kernel runs BPF LSM programs. A program belongs to the
// instance when it uses the instance's counter map. Attest only reads, so a
// gadget can run it again at any time.
func Attest(counters *ebpf.Map, hooks []Hook) error {
	if err := checkHooks(hooks); err != nil {
		return err
	}
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
	if err := hookSignatures(kernel, hooks); err != nil {
		return err
	}
	attached, err := attachedHooks(mapID, kernel, hooks)
	if err != nil {
		return err
	}
	var missing []string
	for _, h := range hooks {
		if !attached[h] {
			missing = append(missing, h.Program+"->"+h.LSM)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("root barrier: no live LSM link for %s", strings.Join(missing, ", "))
	}
	return nil
}

// hookSignatures checks the argument count of each hook in the kernel's BTF. A
// hook that gained an argument would move `ret`, and the program would read
// another argument as the previous verdict.
func hookSignatures(kernel *btf.Spec, hooks []Hook) error {
	args := map[string]int{}
	for _, h := range hooks {
		args[h.LSM] = h.Args
	}
	if err := enforcement.CheckLSMHookArgs(kernel, args); err != nil {
		return fmt.Errorf("root barrier: %w", err)
	}
	return nil
}

// attachedHooks walks every BPF link of the kernel and returns the barrier
// hooks with a live LSM link to a program that uses the map mapID. The walk
// covers every link on the host, and the kernel answers EAGAIN for a link that
// is being created or freed (another gadget starting or stopping). The link
// iterator stops at that error, so the walk is retried a bounded number of
// times.
func attachedHooks(mapID ebpf.MapID, kernel *btf.Spec, hooks []Hook) (map[Hook]bool, error) {
	for attempt := 0; ; attempt++ {
		attached, err := walkHooks(mapID, kernel, hooks)
		if err == nil || !errors.Is(err, unix.EAGAIN) || attempt == walkRetries {
			return attached, err
		}
		time.Sleep(walkRetryDelay)
	}
}

// walkRetries and walkRetryDelay bound the retries (about one second in all).
var (
	walkRetries    = 20
	walkRetryDelay = 50 * time.Millisecond
)

// walkHooks is one walk (replaced in tests).
var walkHooks = walkAttachedHooks

func walkAttachedHooks(mapID ebpf.MapID, kernel *btf.Spec, hooks []Hook) (map[Hook]bool, error) {
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
		hook, ok, err := barrierHook(info.Program, mapID, hooks)
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

// barrierHook returns the hook of the program id when it is a program of
// hooks of the instance that owns mapID.
func barrierHook(id ebpf.ProgramID, mapID ebpf.MapID, hooks []Hook) (Hook, bool, error) {
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
