// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// SetxattrAllowOneParam is the gadget parameter that makes inode_setxattr
// return 1 on an allow (setxattr_allow_one in program.bpf.c).
const SetxattrAllowOneParam = "operator.oci.ebpf.setxattr-allow-one"

// Before Linux 6.11 (commit 61df7b828204, "lsm: fixup the inode xattr
// capability handling"), security_inode_setxattr runs cap_inode_setxattr only
// when the inode_setxattr hooks return 1. The commit added the
// inode_xattr_skipcap hook, so its BPF LSM stub is in the kernel's BTF from
// 6.11 on.
const skipcapHook = "bpf_lsm_inode_xattr_skipcap"

// From Linux 6.9, IMA and EVM are LSMs that run after BPF LSM, and a nonzero
// return stops the hook loop, so a return of 1 would skip their
// inode_setxattr checks. 6.9 added file_post_open for IMA, so its BPF LSM stub
// marks those kernels. Return 1 only before 6.9.
const imaLSMHook = "bpf_lsm_file_post_open"

// SetxattrAllowOne reports whether inode_setxattr must return 1 on an allow:
// the kernel has the old hook semantics, and its verifier accepts a return of
// 1 there. The return value check came with 6.12, and some distribution
// kernels before 6.11 have it too (Ubuntu 6.8): there no BPF program can
// return 1, and the kernel's own BPF LSM default (0) already skips the
// capability check of security.* names, with or without this gadget.
func SetxattrAllowOne() (bool, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false, fmt.Errorf("kernel BTF: %w", err)
	}
	old, err := oldSetxattrSemantics(spec)
	if err != nil || !old {
		return false, err
	}
	return lsmReturnOneLoads()
}

func oldSetxattrSemantics(spec typeFinder) (bool, error) {
	for _, hook := range []string{skipcapHook, imaLSMHook} {
		var fn *btf.Func
		err := spec.TypeByName(hook, &fn)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("kernel BTF %s: %w", hook, err)
		}
		return false, nil
	}
	return true, nil
}

// lsmReturnOneLoads loads (does not attach) an inode_setxattr program that
// returns 1, after one that returns 0 as a control.
func lsmReturnOneLoads() (bool, error) {
	load := func(ret int64) error {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name: "file_xattr_probe", Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "inode_setxattr",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, int32(ret)), asm.Return()}, License: "GPL",
		})
		if err == nil {
			prog.Close()
		}
		return err
	}
	if err := load(0); err != nil {
		return false, fmt.Errorf("inode_setxattr probe program: %w", err)
	}
	return load(1) == nil, nil
}

// SetxattrParams returns the gadget parameter values for this kernel.
func SetxattrParams() (map[string]string, error) {
	one, err := SetxattrAllowOne()
	if err != nil {
		return nil, err
	}
	return map[string]string{SetxattrAllowOneParam: strconv.FormatBool(one)}, nil
}
