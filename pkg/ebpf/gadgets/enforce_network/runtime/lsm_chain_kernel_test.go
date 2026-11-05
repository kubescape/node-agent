//go:build linux && network_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// memberOffset returns the byte offset of a member of a kernel struct.
func memberOffset(t *testing.T, spec *btf.Spec, typ, member string) int16 {
	t.Helper()
	var s *btf.Struct
	if err := spec.TypeByName(typ, &s); err != nil {
		t.Fatal(err)
	}
	for _, m := range s.Members {
		if m.Name == member {
			return int16(m.Offset.Bytes())
		}
	}
	t.Fatalf("struct %s has no member %s", typ, member)
	return 0
}

// attachDenier attaches a BPF LSM program on socket_connect and
// socket_sendmsg that returns -EACCES for an AF_INET or AF_INET6 socket of a
// task in cgroup cgid, and 0 otherwise. The gadget denies with -EPERM, so the
// errno tells which program decided.
func attachDenier(t *testing.T, cgid uint64) {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	sk := memberOffset(t, spec, "socket", "sk")
	if off := memberOffset(t, spec, "sock", "__sk_common"); off != 0 {
		t.Fatalf("sock.__sk_common at offset %d", off)
	}
	family := memberOffset(t, spec, "sock_common", "skc_family")
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentCgroupId.Call(),
		asm.LoadImm(asm.R1, int64(cgid), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R1, "allow"),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.DWord), // struct socket *sock
		asm.LoadMem(asm.R2, asm.R2, sk, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, "allow"),
		asm.LoadMem(asm.R2, asm.R2, family, asm.Half),
		asm.JEq.Imm(asm.R2, unix.AF_INET, "deny"),
		asm.JNE.Imm(asm.R2, unix.AF_INET6, "allow"),
		asm.Mov.Imm(asm.R0, -int32(unix.EACCES)).WithSymbol("deny"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("allow"),
		asm.Return(),
	}
	for _, hook := range []string{"socket_connect", "socket_sendmsg"} {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "net_test_deny", Type: ebpf.LSM,
			AttachType: ebpf.AttachLSMMac, AttachTo: hook, Instructions: insns, License: "GPL"})
		if err != nil {
			t.Fatalf("load denier on %s: %v", hook, err)
		}
		t.Cleanup(func() { prog.Close() })
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			t.Fatalf("attach denier on %s: %v", hook, err)
		}
		t.Cleanup(func() { l.Close() })
	}
}

// TestEarlierBPFLSMDenyHolds checks that the gadget does not replace the deny
// of another BPF LSM program, in both run orders. The BPF trampoline runs the
// newest attached program first, so the program attached last runs first.
func TestEarlierBPFLSMDenyHolds(t *testing.T) {
	f := newKernelFixture(t)
	compiled := matrixPolicy(t)
	for _, denierFirst := range []bool{true, false} {
		name := "denier runs after the gadget"
		if denierFirst {
			name = "denier runs before the gadget"
		}
		t.Run(name, func(t *testing.T) {
			if !denierFirst {
				attachDenier(t, f.container.CgroupID)
			}
			if err := f.start(t, compiled, TierLSM); err != nil {
				t.Fatal(err)
			}
			if denierFirst {
				attachDenier(t, f.container.CgroupID)
			}
			// Unbound task: the gadget allows, the denier denies.
			f.expect(t, f.id, "tcp4", "192.0.2.1", 80, "EACCES")
			f.expect(t, f.id, "udp4-sendto", "192.0.2.1", 53, "EACCES")
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			// Bound to a slot whose rules allow these destinations.
			f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "EACCES")
			f.expect(t, f.id, "udp4-sendto", "203.0.113.5", 54, "EACCES")
			// Denied by both programs: the program that runs first decides.
			want := "EACCES"
			if !denierFirst {
				want = "EPERM"
			}
			f.expect(t, f.id, "tcp4", "192.0.2.1", 80, want)
			f.expect(t, f.id, "udp4-sendto", "192.0.2.1", 53, want)
		})
	}
}
