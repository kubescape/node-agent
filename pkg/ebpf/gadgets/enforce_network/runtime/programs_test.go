// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"maps"
	"os"
	"regexp"
	"testing"
)

// TestProgramsMatchSource keeps Programs equal to the LSM programs of
// ../program.bpf.c, so a new program is checked for a live link.
func TestProgramsMatchSource(t *testing.T) {
	src, err := os.ReadFile("../program.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, m := range regexp.MustCompile(`SEC\("lsm/([a-z_0-9]+)"\)\s*\nint BPF_PROG\(([a-z_0-9]+)`).FindAllStringSubmatch(string(src), -1) {
		want[m[2]] = m[1]
	}
	if len(want) == 0 || !maps.Equal(want, Programs) {
		t.Fatalf("Programs = %v, source has %v", Programs, want)
	}
}
