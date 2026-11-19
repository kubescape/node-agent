// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "testing"

// CredConstants refuses a pressure level at or above the size, and a size
// above the record: the share (size - pressure) / bindings is unsigned.
func TestCredConstantsChecksPressureBelowSize(t *testing.T) {
	for _, c := range []struct {
		pressure, size uint32
		ok             bool
	}{
		{0, 0, true},
		{900, 1200, true},
		{1200, 1200, false},
		{1300, 1200, false},
		{CredRecordMax, 0, false},
		{0, CredRecordMax + 1, false},
		{0, 1200, false}, // the default pressure is above a small size
	} {
		if _, err := CredConstants(0, c.pressure, c.size); (err == nil) != c.ok {
			t.Errorf("pressure %d, size %d: %v", c.pressure, c.size, err)
		}
	}
}
