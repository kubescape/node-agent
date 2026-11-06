// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"github.com/cilium/ebpf"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenLeaderOfThread(t *testing.T) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skip("no /proc")
	}
	pid := strconv.Itoa(os.Getpid())
	thread := ""
	for _, e := range entries {
		if e.Name() != pid {
			thread = e.Name()
		}
	}
	if thread == "" {
		t.Skip("no second thread")
	}
	fd, err := openLeader(thread)
	if err != nil {
		t.Fatalf("leader of thread %s: %v", thread, err)
	}
	unix.Close(fd)
	if _, err := openLeader("999999999"); err == nil {
		t.Fatal("a task that does not exist has no leader")
	}
}

// markMap is an arming map whose Lookup reports every task as already armed,
// or none of them.
type markMap struct {
	fakeMap
	armedAll bool
	puts     int
}

func (m *markMap) Put(interface{}, interface{}) error { m.puts++; return nil }
func (m *markMap) Lookup(_ interface{}, v interface{}) error {
	if m.armedAll {
		*v.(*uint32) = 1
		return nil
	}
	return ebpf.ErrKeyNotExist
}

// Tasks that already carry the mark (children forked after their parent was
// armed) are not progress, so a container that keeps forking converges.
func TestArmThreadsCountsOnlyNewMarks(t *testing.T) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skip("no /proc")
	}
	var tids []string
	for _, e := range entries {
		tids = append(tids, e.Name())
	}
	threads := filepath.Join(t.TempDir(), "cgroup.threads")
	if err := os.WriteFile(threads, []byte(strings.Join(tids, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	armed := &markMap{armedAll: true}
	if n, err := armThreads(armed, threads, 0, map[int]bool{}); err != nil || n != 0 || armed.puts != 0 {
		t.Fatalf("already armed: n=%d puts=%d %v", n, armed.puts, err)
	}
	fresh := &markMap{}
	if n, err := armThreads(fresh, threads, 0, map[int]bool{}); err != nil || n == 0 || n != fresh.puts {
		t.Fatalf("unarmed: n=%d puts=%d %v", n, fresh.puts, err)
	}
}
