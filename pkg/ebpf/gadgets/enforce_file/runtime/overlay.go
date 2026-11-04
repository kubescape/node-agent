// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// fromImage needs struct ovl_inode, which is private to overlayfs. The program
// reads oe (struct ovl_entry *) one pointer after the end of the overlay
// inode's struct inode, and __numlower at the start of struct ovl_entry
// (file_from_image in program.bpf.c). The layout holds on 6.8 and 6.12; the
// check below reads it from the kernel's BTF. When it does not hold, the slots
// do not get filepolicy.SlotFromImage and no file is an image file.

var (
	overlayOnce   sync.Once
	overlayReason string
)

// FromImageUnavailable returns why this kernel's overlay inode layout cannot
// be read for fromImage rules, or "" when it can.
func FromImageUnavailable() string {
	overlayOnce.Do(func() {
		spec, err := btf.LoadKernelModuleSpec("overlay")
		if err != nil {
			// overlay may be built into the kernel.
			if spec, err = btf.LoadKernelSpec(); err != nil {
				overlayReason = fmt.Sprintf("no kernel BTF: %v", err)
				return
			}
		}
		if err := checkOverlayLayout(spec); err != nil {
			overlayReason = err.Error()
		}
	})
	return overlayReason
}

type typeFinder interface {
	TypeByName(name string, typ any) error
}

func member(s *btf.Struct, name string) (btf.Member, bool) {
	for _, m := range s.Members {
		if m.Name == name {
			return m, true
		}
	}
	return btf.Member{}, false
}

// checkOverlayLayout checks the layout that file_from_image reads.
func checkOverlayLayout(spec typeFinder) error {
	var ovl *btf.Struct
	if err := spec.TypeByName("ovl_inode", &ovl); err != nil {
		return fmt.Errorf("overlay BTF has no struct ovl_inode (overlay module not loaded?): %w", err)
	}
	vfs, ok := member(ovl, "vfs_inode")
	if !ok {
		return fmt.Errorf("struct ovl_inode has no vfs_inode")
	}
	inode, ok := btf.UnderlyingType(vfs.Type).(*btf.Struct)
	if !ok || inode.Name != "inode" {
		return fmt.Errorf("ovl_inode.vfs_inode is not a struct inode")
	}
	oe, ok := member(ovl, "oe")
	if !ok {
		return fmt.Errorf("struct ovl_inode has no oe (kernel older than 6.5?)")
	}
	if want := vfs.Offset + btf.Bits(inode.Size*8) + 64; oe.Offset != want {
		return fmt.Errorf("ovl_inode.oe at bit %d, the program reads bit %d", oe.Offset, want)
	}
	ptr, ok := btf.UnderlyingType(oe.Type).(*btf.Pointer)
	if !ok {
		return fmt.Errorf("ovl_inode.oe is not a pointer")
	}
	entry, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
	if !ok || entry.Name != "ovl_entry" {
		return fmt.Errorf("ovl_inode.oe does not point to struct ovl_entry")
	}
	numlower, ok := member(entry, "__numlower")
	if !ok || numlower.Offset != 0 {
		return fmt.Errorf("struct ovl_entry does not start with __numlower")
	}
	if i, ok := btf.UnderlyingType(numlower.Type).(*btf.Int); !ok || i.Size != 4 {
		return fmt.Errorf("ovl_entry.__numlower is not a 4-byte integer")
	}
	return nil
}
