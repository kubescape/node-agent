// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package forkdrift checks that the root barrier copy in the Inspektor Gadget
// fork (gadgets/common/) matches this copy, apart from the import path.
package forkdrift

import (
	"bytes"
	"errors"
	"go/format"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ownPrefix  = "github.com/kubescape/node-agent/pkg/ebpf/gadgets/"
	forkPrefix = "github.com/inspektor-gadget/inspektor-gadget/gadgets/"
	forkModule = "github.com/inspektor-gadget/inspektor-gadget"
)

// Files of the root barrier, relative to the common folder of each copy.
var files = []string{
	"root_barrier.h",
	"rootbarrier/rootbarrier.go",
	"rootbarrier/attest_linux.go",
	"rootbarrier/selftest_linux.go",
	"rootbarrier/verify_linux.go",
	"rootbarrier/rootbarrier_test.go",
	"rootbarrier/attest_linux_test.go",
	"enforcement/lsmhooks.go",
	"enforcement/lsmhooks_test.go",
}

// forkCommon returns the fork's gadgets/common folder: ROOT_BARRIER_FORK_DIR
// (a fork checkout), else the fork version this module pins.
func forkCommon(t *testing.T) string {
	if dir := os.Getenv("ROOT_BARRIER_FORK_DIR"); dir != "" {
		return filepath.Join(dir, "gadgets/common")
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", forkModule).Output()
	if err != nil {
		skipOrFail(t, "cannot locate the pinned fork module: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "gadgets/common")
}

func normalize(t *testing.T, name string, data []byte, rewrite bool) []byte {
	if !strings.HasSuffix(name, ".go") {
		return data
	}
	if rewrite {
		data = bytes.ReplaceAll(data, []byte(ownPrefix), []byte(forkPrefix))
	}
	formatted, err := format.Source(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return formatted
}

func TestForkCopyMatches(t *testing.T) {
	fork := forkCommon(t)
	if _, err := os.Stat(filepath.Join(fork, "root_barrier.h")); errors.Is(err, fs.ErrNotExist) {
		// Until go.mod pins a fork version with the copy (inspektor-gadget
		// #26). From then on the comparison always runs.
		t.Skipf("the fork at %s has no root barrier copy yet", fork)
	}
	for _, name := range files {
		own, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := os.ReadFile(filepath.Join(fork, name))
		if err != nil {
			t.Errorf("%s: missing in the fork copy: %v", name, err)
			continue
		}
		if !bytes.Equal(normalize(t, name, own, true), normalize(t, name, theirs, false)) {
			t.Errorf("%s differs from the fork copy; change both copies together", name)
		}
	}
}

// skipOrFail skips locally, but fails in CI (CI is set): a CI run that cannot
// find the fork must not pass with no comparison.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}
