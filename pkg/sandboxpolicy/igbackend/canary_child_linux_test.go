//go:build linux

package igbackend

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	fileruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/runtime"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
)

// Every hook of the three sections has a trigger, except the three that
// load kernel code (documented as not proven at start). A new hook in a
// gadget fails here until it gets a trigger or a documented exception.
func TestCanaryTriggersCoverSectionHooks(t *testing.T) {
	exempt := map[string]bool{"kernel_read_file": true, "kernel_load_data": true, "kernel_module_request": true}
	for section, programs := range map[string]map[string]string{
		"privilege": privruntime.Programs, "network": netruntime.Programs, "file": fileruntime.Programs,
	} {
		for program, hook := range programs {
			if exempt[hook] {
				if canaryTriggered(hook) {
					t.Errorf("%s: %s has a trigger but is exempt", section, hook)
				}
				continue
			}
			if !canaryTriggered(hook) {
				t.Errorf("%s: program %s, hook %s has no canary trigger", section, program, hook)
			}
		}
	}
	for _, hook := range []string{"kernel_read_file", "kernel_load_data", "kernel_module_request"} {
		if canaryUnprovable(hook) == "" {
			t.Errorf("%s is not reported as not proven", hook)
		}
	}
}

// The base ACL is the xattr form (version 2) of USER_OBJ rw-, GROUP_OBJ
// ---, OTHER ---, each with the undefined id.
func TestCanaryBaseACL(t *testing.T) {
	want := []byte{2, 0, 0, 0,
		0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
		0x04, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,
		0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	if got := canaryBaseACL(); !bytes.Equal(got, want) {
		t.Fatalf("ACL %x, want %x", got, want)
	}
}

// The child writes a refused call's hooks, and canaryResults reads them back.
// EPERM, EACCES, ENOSYS and ENOSPC can stop a call before its hook, and so can
// a fixture the call needs; any other result reached the hook.
func TestCanaryChildResults(t *testing.T) {
	saved := canaryTriggers
	t.Cleanup(func() { canaryTriggers = saved })
	canaryTriggers = []canaryTrigger{
		{[]string{"a"}, func(string) error { return unix.EPERM }},
		{[]string{"b"}, func(string) error { return unix.ENOENT }},
		{[]string{"c"}, func(string) error { return unix.ENOSYS }},
		{[]string{"c"}, func(string) error { return nil }}, // a second call reached it
		// The quota check comes before userns_create's hook; a full disk
		// fails mkdir after path_mkdir.
		{[]string{"userns_create"}, func(string) error { return unix.ENOSPC }},
		{[]string{"path_mkdir"}, func(string) error { return unix.ENOSPC }},
		{[]string{"path_rename"}, func(string) error { return canaryFixtureError{unix.EDQUOT} }},
		{[]string{"path_unlink"}, func(d string) error { return canaryFixture(filepath.Join(d, "no", "such", "dir")) }},
	}
	dir := t.TempDir()
	if rc := runCanaryChild([]string{"a", "b", "c", "userns_create", "path_mkdir", "path_rename", "path_unlink"}, dir); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	got := canaryResults(dir)
	want := map[string]string{"a": "EPERM", "userns_create": "ENOSPC", "path_rename": "fixture-EDQUOT", "path_unlink": "fixture-ENOENT"}
	if len(got) != len(want) {
		t.Fatalf("results %v, want %v", got, want)
	}
	for h, e := range want {
		if got[h] != e {
			t.Fatalf("results %v, want %v", got, want)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the work directory was left: %v", entries)
	}
}

// cred_alloc_blank's call always gets EPERM after its hook: the EPERM counts
// as a refusal only under a seccomp filter.
func TestCanaryRefusalCredAllocBlank(t *testing.T) {
	saved := canarySeccomp
	t.Cleanup(func() { canarySeccomp = saved })
	canarySeccomp = func() bool { return false }
	if why := canaryRefusal("cred_alloc_blank", unix.EPERM); why != "" {
		t.Fatalf("EPERM without seccomp counted as a refusal: %q", why)
	}
	if why := canaryRefusal("cred_alloc_blank", unix.EACCES); why != "EACCES" {
		t.Fatalf("EACCES: %q", why)
	}
	canarySeccomp = func() bool { return true }
	if why := canaryRefusal("cred_alloc_blank", unix.EPERM); why != "EPERM" {
		t.Fatalf("EPERM under seccomp: %q", why)
	}
}

// The io_uring setup reaches the anonymous inode hook on its own: a refused
// personality registration is not charged to that hook.
func TestCanaryUringTriggersSplit(t *testing.T) {
	n := 0 // the userfaultfd trigger and the ring setup trigger
	for _, tr := range canaryTriggers {
		for _, h := range tr.hooks {
			if h == "uring_override_creds" && len(tr.hooks) != 1 {
				t.Fatalf("the personality trigger also lists %v", tr.hooks)
			}
		}
		if len(tr.hooks) == 1 && tr.hooks[0] == "inode_init_security_anon" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want two inode_init_security_anon triggers (userfaultfd, ring setup), got %d", n)
	}
}
