// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf/btf"
)

// LSMHookArgMismatches checks the argument count of each BPF LSM hook in the
// kernel's BTF against the counts its program can handle (hook -> accepted
// counts). It returns one error per hook that does not match, so a caller can
// decide per hook. A BPF LSM program reads the previous BPF verdict, `ret`,
// right after the hook arguments, so a hook with another argument count would
// make it read an argument as the verdict.
func LSMHookArgMismatches(kernel *btf.Spec, hooks map[string][]int) map[string]error {
	bad := map[string]error{}
	for hook, accepted := range hooks {
		var fn *btf.Func
		if err := kernel.TypeByName("bpf_lsm_"+hook, &fn); err != nil {
			bad[hook] = fmt.Errorf("LSM hook %s: %w", hook, err)
			continue
		}
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok {
			bad[hook] = fmt.Errorf("LSM hook %s has no function prototype", hook)
			continue
		}
		known := false
		for _, n := range accepted {
			known = known || len(proto.Params) == n
		}
		if !known {
			bad[hook] = fmt.Errorf("LSM hook %s has %d arguments, the program handles %v", hook, len(proto.Params), accepted)
		}
	}
	return bad
}

// CheckLSMHookArgs is LSMHookArgMismatches for programs with one signature
// per hook: it fails when any hook does not match.
func CheckLSMHookArgs(kernel *btf.Spec, hooks map[string]int) error {
	accepted := make(map[string][]int, len(hooks))
	for hook, n := range hooks {
		accepted[hook] = []int{n}
	}
	return JoinHookMismatches(LSMHookArgMismatches(kernel, accepted))
}

// JoinHookMismatches joins the errors of LSMHookArgMismatches in hook order.
func JoinHookMismatches(bad map[string]error) error {
	hooks := make([]string, 0, len(bad))
	for hook := range bad {
		hooks = append(hooks, hook)
	}
	sort.Strings(hooks)
	errs := make([]error, 0, len(hooks))
	for _, hook := range hooks {
		errs = append(errs, bad[hook])
	}
	return errors.Join(errs...)
}
