// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"os"
	"strconv"
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
