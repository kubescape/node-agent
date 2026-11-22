//go:build !linux || !sandboxpolicy_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package igbackend

import (
	"os"
	"testing"
)

// TestMain keeps the unit tests off the host's pinned BPF state: the sections
// they start on fake engines reset their pins before the first start, and a
// run as root would remove the real ones (a kernel test running next to them
// then loses its pinned maps). The kernel tests keep the real reset.
func TestMain(m *testing.M) {
	removePinnedMaps = func(string) error { return nil }
	os.Exit(m.Run())
}
