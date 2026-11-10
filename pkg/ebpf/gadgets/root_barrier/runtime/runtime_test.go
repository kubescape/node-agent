// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckLevel(t *testing.T) {
	root, old := t.TempDir(), cgroupRoot
	cgroupRoot = root
	t.Cleanup(func() { cgroupRoot = old })
	mk := func(rel string) uint64 {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(dir, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	shallow := "/kubepods/pod1/c1"
	id := mk(shallow)
	deep := "/" + strings.Repeat("d/", coveredLevels) + "leaf"
	deepID := mk(deep)
	for name, tc := range map[string]struct {
		c  Cgroup
		ok bool
	}{
		"audit exact needs nothing":    {Cgroup{ID: 1}, true},
		"enforce with its path":        {Cgroup{ID: id, Path: shallow, Enforce: true}, true},
		"subtree with its path":        {Cgroup{ID: id, Path: shallow, Subtree: true}, true},
		"enforce without a path":       {Cgroup{ID: id, Enforce: true}, false},
		"subtree without a path":       {Cgroup{ID: id, Subtree: true}, false},
		"enforce too deep":             {Cgroup{ID: deepID, Path: deep, Enforce: true}, false},
		"enforce with another cgroup":  {Cgroup{ID: id + 1000, Path: shallow, Enforce: true}, false},
		"enforce with a relative path": {Cgroup{ID: id, Path: "/kubepods/../kubepods/pod1/c1", Enforce: true}, false},
	} {
		if err := checkLevel(tc.c); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
