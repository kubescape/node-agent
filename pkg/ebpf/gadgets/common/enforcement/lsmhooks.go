// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// CheckLSMHookArgs checks the argument count of each BPF LSM hook (name ->
// count) in the kernel's BTF. A BPF LSM program reads the previous BPF verdict,
// `ret`, right after the hook arguments, so a hook with another argument count
// would make it read an argument as the verdict. Call it before the programs
// are loaded, and refuse the kernel on an error.
func CheckLSMHookArgs(kernel *btf.Spec, hooks map[string]int) error {
	for hook, args := range hooks {
		var fn *btf.Func
		if err := kernel.TypeByName("bpf_lsm_"+hook, &fn); err != nil {
			return fmt.Errorf("LSM hook %s: %w", hook, err)
		}
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok || len(proto.Params) != args {
			return fmt.Errorf("LSM hook %s has an unexpected signature; this kernel is not supported", hook)
		}
	}
	return nil
}
