// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"os"
	"path/filepath"
)

// PinRoot is where the loader pins maps declared pinned by name (../pin.h).
const PinRoot = "/sys/fs/bpf"

// RemovePinnedMaps removes the pinned maps of a section (prefix: its
// SANDBOX_SECTION). A running instance keeps its maps; the next load starts
// from empty state. Use it when restart survival is off, and in tests.
func RemovePinnedMaps(prefix string) error {
	if prefix == "" {
		return errors.New("a section prefix is required")
	}
	paths, err := filepath.Glob(filepath.Join(PinRoot, prefix+"*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
