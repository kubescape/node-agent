// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// ProgramIDs gives every hook the ID of its program, and refuses a hook with
// no program or with more than one.
func TestProgramIDs(t *testing.T) {
	defer func(w func(ebpf.MapID, []Hook) (map[string][]ebpf.ProgramID, error)) { walkPrograms = w }(walkPrograms)
	all := map[string][]ebpf.ProgramID{}
	for i, h := range Hooks {
		all[h.Program] = []ebpf.ProgramID{ebpf.ProgramID(100 + i)}
	}
	ids := func(mutate func(map[string][]ebpf.ProgramID)) map[string][]ebpf.ProgramID {
		found := map[string][]ebpf.ProgramID{}
		for name, list := range all {
			found[name] = append([]ebpf.ProgramID(nil), list...)
		}
		mutate(found)
		return found
	}

	for name, tc := range map[string]struct {
		found map[string][]ebpf.ProgramID
		want  string
	}{
		"every program": {all, ""},
		"a missing one": {ids(func(f map[string][]ebpf.ProgramID) { delete(f, "rb_chroot") }), "no loaded program for rb_chroot->path_chroot"},
		"two of a name": {ids(func(f map[string][]ebpf.ProgramID) { f["rb_capable"] = append(f["rb_capable"], 999) }), "all carry rb_capable"},
	} {
		walkPrograms = func(ebpf.MapID, []Hook) (map[string][]ebpf.ProgramID, error) { return tc.found, nil }
		got, err := programIDs(1, Hooks)
		if tc.want != "" {
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: got %v, want an error with %q", name, err, tc.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, h := range got {
			if h.ID != ebpf.ProgramID(100+i) || h.Program != Hooks[i].Program || h.LSM != Hooks[i].LSM {
				t.Errorf("%s: hook %d is %+v", name, i, h)
			}
		}
		if Hooks[0].ID != 0 {
			t.Fatal("ProgramIDs must not change Hooks")
		}
		if err := checkHooks(got); err != nil {
			t.Errorf("%s: hooks with IDs: %v", name, err)
		}
	}
}

// A hook that already has an ID (WithProgramID) keeps it, even when its name
// matches no program.
func TestProgramIDsKeepsID(t *testing.T) {
	defer func(w func(ebpf.MapID, []Hook) (map[string][]ebpf.ProgramID, error)) { walkPrograms = w }(walkPrograms)
	found := map[string][]ebpf.ProgramID{}
	for i, h := range Hooks {
		found[h.Program] = []ebpf.ProgramID{ebpf.ProgramID(100 + i)}
	}
	delete(found, "rb_task_alloc")
	walkPrograms = func(ebpf.MapID, []Hook) (map[string][]ebpf.ProgramID, error) { return found, nil }
	got, err := programIDs(1, withID(Hooks, "task_alloc", "opaque_real_own", 7))
	if err != nil {
		t.Fatal(err)
	}
	if got[3].ID != 7 || got[0].ID != 100 {
		t.Fatalf("got %+v and %+v, want ID 7 kept and ID 100 found", got[3], got[0])
	}
}
