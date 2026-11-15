// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// CheckLinks matches each link to the program ID, not to the name, and names
// the hook of a missing link. A transient EAGAIN is retried.
func TestCheckLinks(t *testing.T) {
	defer func(w func() (map[ebpf.ProgramID]map[string]bool, error), r int, d time.Duration) {
		walkLinks, walkRetries, walkRetryDelay = w, r, d
	}(walkLinks, walkRetries, walkRetryDelay)
	walkRetries, walkRetryDelay = 3, 0

	ids := map[Hook]ebpf.ProgramID{}
	all := map[ebpf.ProgramID]map[string]bool{}
	for i, h := range Hooks {
		id := ebpf.ProgramID(100 + i)
		ids[h] = id
		all[id] = map[string]bool{"bpf_lsm_" + h.LSM: true}
	}
	chroot := Hooks[0]
	without := func(mutate func(map[ebpf.ProgramID]map[string]bool)) map[ebpf.ProgramID]map[string]bool {
		links := map[ebpf.ProgramID]map[string]bool{}
		for id, targets := range all {
			links[id] = map[string]bool{}
			for target := range targets {
				links[id][target] = true
			}
		}
		mutate(links)
		return links
	}

	for name, tc := range map[string]struct {
		links map[ebpf.ProgramID]map[string]bool
		want  string
	}{
		"every link live": {all, ""},
		"a link detached": {without(func(l map[ebpf.ProgramID]map[string]bool) { delete(l, ids[chroot]) }),
			"rb_chroot->path_chroot (program 100)"},
		// Another program (for example of a newer instance, with the
		// same name) is linked to the hook, but not this one.
		"another program on the hook": {without(func(l map[ebpf.ProgramID]map[string]bool) {
			delete(l, ids[chroot])
			l[999] = map[string]bool{"bpf_lsm_path_chroot": true}
		}), "rb_chroot->path_chroot (program 100)"},
		"the program linked to another hook": {without(func(l map[ebpf.ProgramID]map[string]bool) {
			l[ids[chroot]] = map[string]bool{"bpf_lsm_sb_mount": true}
		}), "rb_chroot->path_chroot (program 100)"},
	} {
		walkLinks = func() (map[ebpf.ProgramID]map[string]bool, error) { return tc.links, nil }
		err := CheckLinks(ids)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want an error naming %s", name, err, tc.want)
		}
	}

	if err := CheckLinks(nil); err == nil {
		t.Error("no program IDs must be an error, never healthy")
	}

	calls := 0
	busy := fmt.Errorf("root barrier: listing BPF links: %w", unix.EAGAIN)
	walkLinks = func() (map[ebpf.ProgramID]map[string]bool, error) {
		calls++
		if calls < 3 {
			return nil, busy
		}
		return all, nil
	}
	if err := CheckLinks(ids); err != nil || calls != 3 {
		t.Fatalf("transient EAGAIN: %v after %d walks", err, calls)
	}
	calls = 0
	walkLinks = func() (map[ebpf.ProgramID]map[string]bool, error) { calls++; return nil, busy }
	if err := CheckLinks(ids); !errors.Is(err, unix.EAGAIN) || calls != walkRetries+1 {
		t.Fatalf("persistent EAGAIN: %v after %d walks", err, calls)
	}
}
